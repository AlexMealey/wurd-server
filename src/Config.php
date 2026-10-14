<?php
// Server settings, read from the environment. Anything invalid stops the server rather than
// running it with a weaker setting. Tokens aren't settings: users request their own (see Users).
declare(strict_types=1);

namespace Wurd;

final class ConfigError extends \RuntimeException {}

final readonly class Config
{
    public const string DATA_DIR = '/data';

    /** @param list<string> $allowedOrigins */
    public function __construct(
        public int $maxFileBytes,
        public int $maxTotalBytes,
        public int $maxFiles,
        public array $allowedOrigins,
    ) {}

    public static function fromEnvironment(): self
    {
        return new self(
            maxFileBytes: self::megabytes('WURD_MAX_FILE_MB', 25),
            maxTotalBytes: self::megabytes('WURD_MAX_TOTAL_MB', 1024),
            maxFiles: self::positiveInt('WURD_MAX_FILES', 5000),
            allowedOrigins: self::origins(),
        );
    }

    // Addresses Apache trusts to report the client's IP (the TLS proxy). Apache reads the variable itself;
    // this only checks it, since it's pasted into Apache's configuration.
    public static function checkTrustedProxies(): void
    {
        foreach (self::list('WURD_TRUSTED_PROXIES') as $entry) {
            [$ip, $bits] = array_pad(explode('/', $entry, 2), 2, null);
            $valid = filter_var($ip, FILTER_VALIDATE_IP) !== false
                && ($bits === null || (ctype_digit($bits) && (int) $bits <= (str_contains($ip, ':') ? 128 : 32)));
            if (!$valid) {
                throw new ConfigError("WURD_TRUSTED_PROXIES: \"{$entry}\" isn't an IP address or CIDR range.");
            }
        }
    }

    private static function positiveInt(string $name, int $default): int
    {
        $value = getenv($name);
        if ($value === false || $value === '') {
            return $default;
        }
        if (!preg_match('/^[1-9][0-9]{0,8}$/', $value)) {
            throw new ConfigError("{$name} must be a whole number above 0.");
        }
        return (int) $value;
    }

    private static function megabytes(string $name, int $default): int
    {
        return self::positiveInt($name, $default) * 1024 * 1024;
    }

    // Origins allowed to call the API from another page, e.g. "http://192.168.1.20:8000" or "null" for file:// pages.
    // Empty by default: the frontend served by this server is same-origin and needs no CORS.
    private static function origins(): array
    {
        $origins = self::list('WURD_ALLOWED_ORIGINS');
        foreach ($origins as $origin) {
            if ($origin !== 'null' && !preg_match('#^https?://[a-z0-9.\-]+(:[0-9]{1,5})?$|^https?://\[[0-9a-f:.]+\](:[0-9]{1,5})?$#', $origin)) {
                throw new ConfigError("WURD_ALLOWED_ORIGINS: \"{$origin}\" isn't an origin. Use scheme://host[:port] in lower case, or null.");
            }
        }
        return $origins;
    }

    /** @return list<string> */
    private static function list(string $name): array
    {
        return preg_split('/[\s,]+/', (string) getenv($name), -1, PREG_SPLIT_NO_EMPTY);
    }
}
