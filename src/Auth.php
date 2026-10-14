<?php
// Bearer-token check. A single shared token, no cookies or sessions (so no CSRF), and a cap on
// failed attempts per client IP.
declare(strict_types=1);

namespace Wurd;

final readonly class Auth
{
    private const int MAX_FAILURES = 10;
    private const int WINDOW_SECONDS = 600;

    public function __construct(private \PDO $db, private string $token) {}

    public function check(string $ip, ?string $authorization): void
    {
        $since = time() - self::WINDOW_SECONDS;
        $count = $this->db->prepare('SELECT COUNT(*) FROM auth_failures WHERE ip = ? AND at > ?');
        $count->execute([$ip, $since]);
        if ((int) $count->fetchColumn() >= self::MAX_FAILURES) {
            throw new HttpError(429, 'Too many wrong tokens. Try again in a few minutes.', ['Retry-After' => (string) self::WINDOW_SECONDS]);
        }

        $given = preg_match('/^Bearer +(\S+)$/i', trim($authorization ?? ''), $m) ? $m[1] : '';
        // Comparing digests keeps the check constant-time whatever the length of the given token
        if (hash_equals(hash('sha256', $this->token), hash('sha256', $given))) {
            return;
        }

        $this->db->prepare('INSERT INTO auth_failures (ip, at) VALUES (?, ?)')->execute([$ip, time()]);
        $this->db->prepare('DELETE FROM auth_failures WHERE at <= ?')->execute([$since]);
        throw new HttpError(401, 'Missing or wrong token.', ['WWW-Authenticate' => 'Bearer']);
    }
}
