<?php
// Per-user tokens. A token is "wurd_<id>_<secret>": the id finds the user's row, the secret proves it.
// The database keeps only a salted verifier of the secret, never the token. Each user's files are encrypted
// with a random vault key, stored wrapped under a key derived from the secret and the server's pepper, so
// opening a vault needs both the token and the pepper, which lives outside /data.
declare(strict_types=1);

namespace Wurd;

// The user a request was made by, and the key their files are encrypted with
final readonly class User
{
    public function __construct(public string $id, #[\SensitiveParameter] public string $fileKey) {}
}

final readonly class Users
{
    private const int MAX_REQUESTS = 5;
    private const int WINDOW_SECONDS = 3600;
    private const string TOKEN_PATTERN = '/^wurd_([0-9a-f]{16})_([0-9a-f]{64})$/';
    // 1: verifier and file key straight from the secret (before the pepper). 2: peppered, wrapped vault key.
    private const int SCHEME = 2;

    public function __construct(private \PDO $db, #[\SensitiveParameter] private string $pepper) {}

    // Run at startup: remembers which pepper /data was set up with, and refuses to start with another one.
    // A wrong pepper would otherwise only show up as every token being refused.
    public static function checkPepper(\PDO $db, #[\SensitiveParameter] string $pepper): void
    {
        $check = hash_hmac('sha256', 'wurd pepper check', $pepper, true);
        $statement = $db->prepare("SELECT value FROM settings WHERE name = 'pepper_check'");
        $statement->execute();
        $stored = $statement->fetchColumn();
        if ($stored === false) {
            $insert = $db->prepare("INSERT INTO settings (name, value) VALUES ('pepper_check', ?)");
            $insert->bindValue(1, $check, \PDO::PARAM_LOB);
            $insert->execute();
        } elseif (!hash_equals($stored, $check)) {
            throw new ConfigError("WURD_PEPPER isn't the one this server's data was set up with. Restore the original value: without it, no vault can be opened.");
        }
    }

    // Creates a user and returns their token. It's shown once; only the verifier is kept.
    public function issue(string $ip): string
    {
        $since = time() - self::WINDOW_SECONDS;
        $count = $this->db->prepare('SELECT COUNT(*) FROM token_requests WHERE ip = ? AND at > ?');
        $count->execute([$ip, $since]);
        if ((int) $count->fetchColumn() >= self::MAX_REQUESTS) {
            throw new HttpError(429, 'Too many tokens requested from this address. Try again later.', ['Retry-After' => (string) self::WINDOW_SECONDS]);
        }

        $id = bin2hex(random_bytes(8));
        $secret = random_bytes(32);
        $salt = random_bytes(16);
        $vaultKey = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
        [$verifier, $kek] = $this->derive($secret, $salt);
        $insert = $this->db->prepare('INSERT INTO users (id, salt, verifier, wrapped_key, scheme, created_at) VALUES (?, ?, ?, ?, ?, ?)');
        $insert->bindValue(1, $id);
        $insert->bindValue(2, $salt, \PDO::PARAM_LOB);
        $insert->bindValue(3, $verifier, \PDO::PARAM_LOB);
        $insert->bindValue(4, self::wrap($vaultKey, $kek, $id), \PDO::PARAM_LOB);
        $insert->bindValue(5, self::SCHEME, \PDO::PARAM_INT);
        $insert->bindValue(6, Store::now());
        $insert->execute();
        sodium_memzero($vaultKey);
        sodium_memzero($kek);

        $this->db->prepare('INSERT INTO token_requests (ip, at) VALUES (?, ?)')->execute([$ip, time()]);
        $this->db->prepare('DELETE FROM token_requests WHERE at <= ?')->execute([$since]);
        $token = "wurd_{$id}_" . bin2hex($secret);
        sodium_memzero($secret);
        return $token;
    }

    public function authenticate(#[\SensitiveParameter] string $token): ?User
    {
        [$id, $secret] = preg_match(self::TOKEN_PATTERN, $token, $m) ? [$m[1], hex2bin($m[2])] : ['', str_repeat("\0", 32)];
        $statement = $this->db->prepare('SELECT salt, verifier, wrapped_key, scheme FROM users WHERE id = ?');
        $statement->execute([$id]);
        $row = $statement->fetch();
        try {
            if ($row === false) {
                // An unknown user still costs one derivation, so timing doesn't tell which IDs exist
                [$verifier, $kek] = $this->derive($secret, str_repeat("\0", 16));
                sodium_memzero($kek);
                return null;
            }
            $vaultKey = $row['scheme'] === 1 ? $this->upgrade($id, $secret, $row) : $this->open($id, $secret, $row);
        } finally {
            sodium_memzero($secret);
        }
        if ($vaultKey === null) {
            return null;
        }
        $this->db->prepare('UPDATE users SET last_used_at = ? WHERE id = ?')->execute([Store::now(), $id]);
        return new User($id, $vaultKey);
    }

    // The vault key of a current (scheme 2) user, or null if the secret is wrong
    private function open(string $id, #[\SensitiveParameter] string $secret, array $row): ?string
    {
        [$verifier, $kek] = $this->derive($secret, $row['salt']);
        try {
            if (!hash_equals($row['verifier'], $verifier)) {
                return null;
            }
            // The secret was right, so a key that won't unwrap means the row was damaged
            return self::unwrap($row['wrapped_key'], $kek, $id) ?? throw new \RuntimeException("User {$id}'s vault key failed to unwrap");
        } finally {
            sodium_memzero($kek);
        }
    }

    // Checks a user from before the pepper (scheme 1) and moves them to scheme 2. Their files stay as they are:
    // the key they were encrypted with becomes the user's wrapped vault key.
    private function upgrade(string $id, #[\SensitiveParameter] string $secret, array $row): ?string
    {
        if (!hash_equals($row['verifier'], hash_hkdf('sha256', $secret, 32, 'wurd token', $row['salt']))) {
            return null;
        }
        $vaultKey = hash_hkdf('sha256', $secret, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, 'wurd files', $row['salt']);
        [$verifier, $kek] = $this->derive($secret, $row['salt']);
        $update = $this->db->prepare('UPDATE users SET verifier = ?, wrapped_key = ?, scheme = ? WHERE id = ? AND scheme = 1');
        $update->bindValue(1, $verifier, \PDO::PARAM_LOB);
        $update->bindValue(2, self::wrap($vaultKey, $kek, $id), \PDO::PARAM_LOB);
        $update->bindValue(3, self::SCHEME, \PDO::PARAM_INT);
        $update->bindValue(4, $id);
        $update->execute();
        sodium_memzero($kek);
        return $vaultKey;
    }

    // [verifier, key-encryption key]. The pepper keys the first step, so a copy of /data alone, even with a
    // token, opens nothing.
    /** @return array{string, string} */
    private function derive(#[\SensitiveParameter] string $secret, string $salt): array
    {
        $ikm = hash_hmac('sha256', $secret, $this->pepper, true);
        $keys = [
            hash_hkdf('sha256', $ikm, 32, 'wurd token v2', $salt),
            hash_hkdf('sha256', $ikm, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 'wurd vault key v2', $salt),
        ];
        sodium_memzero($ikm);
        return $keys;
    }

    // Nonce + XChaCha20-Poly1305, bound to the user's ID so one user's wrapped key can't be moved to another
    private static function wrap(#[\SensitiveParameter] string $vaultKey, #[\SensitiveParameter] string $kek, string $id): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        return $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($vaultKey, "wurd vault key|{$id}", $nonce, $kek);
    }

    private static function unwrap(?string $wrapped, #[\SensitiveParameter] string $kek, string $id): ?string
    {
        if ($wrapped === null || strlen($wrapped) <= SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            return null;
        }
        $nonce = substr($wrapped, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $sealed = substr($wrapped, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $key = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($sealed, "wurd vault key|{$id}", $nonce, $kek);
        return $key === false ? null : $key;
    }
}
