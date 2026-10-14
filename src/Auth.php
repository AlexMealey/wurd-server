<?php
// Bearer-token check against the users table. No cookies or sessions (so no CSRF), and a cap on
// failed attempts per client IP.
declare(strict_types=1);

namespace Wurd;

final readonly class Auth
{
    private const int MAX_FAILURES = 10;
    private const int WINDOW_SECONDS = 600;

    public function __construct(private \PDO $db) {}

    public function check(string $ip, ?string $authorization): User
    {
        $since = time() - self::WINDOW_SECONDS;
        $count = $this->db->prepare('SELECT COUNT(*) FROM auth_failures WHERE ip = ? AND at > ?');
        $count->execute([$ip, $since]);
        if ((int) $count->fetchColumn() >= self::MAX_FAILURES) {
            throw new HttpError(429, 'Too many wrong tokens. Try again in a few minutes.', ['Retry-After' => (string) self::WINDOW_SECONDS]);
        }

        $given = preg_match('/^Bearer +(\S+)$/i', trim($authorization ?? ''), $m) ? $m[1] : '';
        $user = new Users($this->db)->authenticate($given);
        if ($user !== null) {
            return $user;
        }

        $this->db->prepare('INSERT INTO auth_failures (ip, at) VALUES (?, ?)')->execute([$ip, time()]);
        $this->db->prepare('DELETE FROM auth_failures WHERE at <= ?')->execute([$since]);
        throw new HttpError(401, 'Missing or wrong token.', ['WWW-Authenticate' => 'Bearer']);
    }
}
