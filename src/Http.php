<?php
// Request and response helpers. Security headers (CSP, nosniff, no-store) are set by Apache for every
// /api response, including Apache's own error pages; CORS is set here because it depends on the config.
declare(strict_types=1);

namespace Wurd;

// An error with a message that is safe to show the client
final class HttpError extends \RuntimeException
{
    /** @param array<string, string> $headers */
    public function __construct(public readonly int $status, string $message, public readonly array $headers = [])
    {
        parent::__construct($message);
    }
}

final class Http
{
    private const string ALLOWED_METHODS = 'GET, POST, PUT, DELETE';
    private const string ALLOWED_HEADERS = 'Authorization, Content-Type, If-Match, X-File-Name';

    /** @var array<string, string>|null lower-cased header name => value */
    private static ?array $headers = null;

    public static function method(): string
    {
        return $_SERVER['REQUEST_METHOD'] ?? 'GET';
    }

    public static function path(): string
    {
        return parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    }

    public static function clientIp(): string
    {
        // Apache's mod_remoteip has already swapped in the real client address when behind the TLS proxy
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public static function header(string $name): ?string
    {
        // getallheaders() includes Authorization, which Apache keeps out of $_SERVER
        self::$headers ??= array_change_key_case(getallheaders(), CASE_LOWER);
        return self::$headers[strtolower($name)] ?? null;
    }

    // Length of the request body. Bodies must declare it up front, so oversized ones are refused before reading.
    public static function contentLength(int $max): int
    {
        $length = $_SERVER['CONTENT_LENGTH'] ?? '';
        if (!preg_match('/^[0-9]{1,15}$/', $length)) {
            throw new HttpError(411, 'The request needs a Content-Length header.');
        }
        if ((int) $length > $max) {
            throw new HttpError(413, 'The file is larger than this server allows (' . intdiv($max, 1024 * 1024) . ' MB).');
        }
        return (int) $length;
    }

    // The revision from an If-Match header ("3"), required for every change to an existing file
    public static function ifMatch(): int
    {
        $value = self::header('If-Match');
        if ($value === null) {
            throw new HttpError(428, 'Changing a file needs an If-Match header with the ETag it was read with.');
        }
        if (!preg_match('/^"([1-9][0-9]{0,15})"$/', trim($value), $m)) {
            throw new HttpError(400, 'If-Match must be the ETag the file was read with, e.g. "3".');
        }
        return (int) $m[1];
    }

    // Adds CORS headers when the request comes from an allowed origin. Returns whether it did.
    /** @param list<string> $allowedOrigins */
    public static function cors(array $allowedOrigins): bool
    {
        header('Vary: Origin');
        $origin = self::header('Origin');
        if ($origin === null || !in_array($origin, $allowedOrigins, true)) {
            return false;
        }
        header("Access-Control-Allow-Origin: {$origin}");
        header('Access-Control-Expose-Headers: ETag');
        return true;
    }

    /** @param list<string> $allowedOrigins */
    public static function preflight(array $allowedOrigins): never
    {
        if (!self::cors($allowedOrigins)) {
            throw new HttpError(403, 'This origin is not allowed to use the API.');
        }
        header('Access-Control-Allow-Methods: ' . self::ALLOWED_METHODS);
        header('Access-Control-Allow-Headers: ' . self::ALLOWED_HEADERS);
        header('Access-Control-Max-Age: 600');
        self::noContent();
    }

    /** @param array<string, string> $headers */
    public static function json(int $status, mixed $body, array $headers = []): never
    {
        http_response_code($status);
        foreach ($headers as $name => $value) {
            header("{$name}: {$value}");
        }
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public static function noContent(): never
    {
        http_response_code(204);
        exit;
    }

    public static function error(HttpError $e): never
    {
        self::json($e->status, ['error' => $e->getMessage()], $e->headers);
    }

    // Sends a stored file from its decrypted chunks. Always as an opaque download, never with its own type,
    // so a stored .html page can't run in the browser on this server's origin.
    /** @param \Generator<string> $chunks */
    public static function download(\Generator $chunks, array $meta): never
    {
        // Store::read authenticates the whole file before its first chunk, which happens here, before any
        // header goes out: a bad key or damaged file is a clean error
        $chunks->current();
        $fallback = preg_replace('/[^A-Za-z0-9._ -]/', '_', $meta['name']);
        header('Content-Type: application/octet-stream');
        header("Content-Length: {$meta['size']}");
        header("Content-Disposition: attachment; filename=\"{$fallback}\"; filename*=UTF-8''" . rawurlencode($meta['name']));
        header("ETag: \"{$meta['rev']}\"");
        try {
            for (; $chunks->valid(); $chunks->next()) {
                echo $chunks->current();
            }
        } catch (\Throwable $e) {
            // Only a read error can get here now. The headers are gone, so cut the body short: the client sees a
            // failed download, not a wrong file
            error_log('wurd: ' . $e::class . ": {$e->getMessage()}");
        }
        exit;
    }
}
