<?php
// Per-user tokens. A token is "wurd_<id>_<secret>": the id finds the user's row, the secret proves it.
// The database keeps only a salted verifier of the secret, never the token, and each user's file key is
// derived from the secret on every request, so the server can't open anyone's files without their token.
declare(strict_types=1);

namespace Wurd;

// The user a request was made by, and the key their files are encrypted with
final readonly class User
{
    public function __construct(public string $id, public string $fileKey) {}
}

final readonly class Users
{
    private const int MAX_REQUESTS = 5;
    private const int WINDOW_SECONDS = 3600;
    private const string TOKEN_PATTERN = '/^wurd_([0-9a-f]{16})_([0-9a-f]{64})$/';

    public function __construct(private \PDO $db) {}

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
        $insert = $this->db->prepare('INSERT INTO users (id, salt, verifier, created_at) VALUES (?, ?, ?, ?)');
        $insert->bindValue(1, $id);
        $insert->bindValue(2, $salt, \PDO::PARAM_LOB);
        $insert->bindValue(3, self::verifier($secret, $salt), \PDO::PARAM_LOB);
        $insert->bindValue(4, Store::now());
        $insert->execute();

        $this->db->prepare('INSERT INTO token_requests (ip, at) VALUES (?, ?)')->execute([$ip, time()]);
        $this->db->prepare('DELETE FROM token_requests WHERE at <= ?')->execute([$since]);
        return "wurd_{$id}_" . bin2hex($secret);
    }

    public function authenticate(string $token): ?User
    {
        [$id, $secret] = preg_match(self::TOKEN_PATTERN, $token, $m) ? [$m[1], hex2bin($m[2])] : ['', str_repeat("\0", 32)];
        $statement = $this->db->prepare('SELECT salt, verifier FROM users WHERE id = ?');
        $statement->execute([$id]);
        $row = $statement->fetch();
        // An unknown user still costs one derivation, so timing doesn't tell which IDs exist
        $salt = $row === false ? str_repeat("\0", 16) : $row['salt'];
        $matches = hash_equals($row === false ? str_repeat("\0", 32) : $row['verifier'], self::verifier($secret, $salt));
        if ($row === false || !$matches) {
            return null;
        }
        $this->db->prepare('UPDATE users SET last_used_at = ? WHERE id = ?')->execute([Store::now(), $id]);
        return new User($id, hash_hkdf('sha256', $secret, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, 'wurd files', $salt));
    }

    private static function verifier(string $secret, string $salt): string
    {
        return hash_hkdf('sha256', $secret, 32, 'wurd token', $salt);
    }
}
