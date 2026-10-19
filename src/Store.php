<?php
// The file store: metadata in SQLite, contents in /data/files named by random ID and encrypted with the
// owner's key (see Vault). Each user sees only their own files. Stored files are never parsed or converted;
// the browser does all of that. User-supplied names are only ever data, never part of a path.
declare(strict_types=1);

namespace Wurd;

final readonly class Store
{
    // Extensions Wurd opens and saves, and the format each one is stored as
    private const array FORMATS = ['docx' => 'docx', 'odt' => 'odt', 'doc' => 'doc', 'html' => 'html', 'htm' => 'html', 'txt' => 'txt', 'wurd' => 'wurd'];
    private const int MAX_NAME_BYTES = 200;
    private const string FIELDS = 'id, name, format, size, rev, updated_at AS updatedAt';

    public function __construct(private \PDO $db, private Config $config, private User $user) {}

    public static function connect(): \PDO
    {
        $db = new \PDO('sqlite:' . Config::DATA_DIR . '/wurd.sqlite', options: [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);
        // Apache runs several PHP processes; a writer waits for another rather than failing
        $db->exec('PRAGMA busy_timeout = 5000');
        return $db;
    }

    // Run once at startup: creates the folders and tables, and clears uploads a restart cut short
    public static function setUp(): void
    {
        foreach (['files', 'tmp'] as $dir) {
            $path = Config::DATA_DIR . "/{$dir}";
            if (!is_dir($path) && !mkdir($path, 0700)) {
                throw new ConfigError("Can't create {$path}. The /data volume must be writable by www-data (uid 33).");
            }
        }
        foreach (glob(Config::DATA_DIR . '/tmp/*') ?: [] as $leftover) {
            unlink($leftover);
        }
        $db = self::connect();
        $db->exec('PRAGMA journal_mode = WAL');
        $db->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS users (
              id           TEXT PRIMARY KEY,
              salt         BLOB NOT NULL,
              verifier     BLOB NOT NULL,
              wrapped_key  BLOB,
              scheme       INTEGER NOT NULL DEFAULT 1,
              created_at   TEXT NOT NULL,
              last_used_at TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
              id         TEXT PRIMARY KEY,
              user_id    TEXT REFERENCES users (id),
              name       TEXT NOT NULL,
              format     TEXT NOT NULL,
              size       INTEGER NOT NULL,
              rev        INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_failures (ip TEXT NOT NULL, at INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS auth_failures_ip_at ON auth_failures (ip, at);
            CREATE TABLE IF NOT EXISTS token_requests (ip TEXT NOT NULL, at INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS token_requests_ip_at ON token_requests (ip, at);
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL);
            SQL);
        // Files stored before per-user tokens have no owner (and aren't encrypted), so they're never listed
        self::addColumn($db, 'files', 'user_id', 'TEXT REFERENCES users (id)');
        $db->exec('CREATE INDEX IF NOT EXISTS files_user_updated ON files (user_id, updated_at)');
        // Users from before the pepper are scheme 1 until their next request upgrades them (see Users)
        self::addColumn($db, 'users', 'wrapped_key', 'BLOB');
        self::addColumn($db, 'users', 'scheme', 'INTEGER NOT NULL DEFAULT 1');
    }

    // Adds a column to a table created by an older version
    private static function addColumn(\PDO $db, string $table, string $column, string $definition): void
    {
        if (!in_array($column, array_column($db->query("PRAGMA table_info({$table})")->fetchAll(), 'name'), true)) {
            $db->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$definition}");
        }
    }

    // [name, format] from an X-File-Name header (percent-encoded UTF-8)
    /** @return array{string, string} */
    public static function parseName(?string $header): array
    {
        if ($header === null) {
            throw new HttpError(400, 'Send the file name in an X-File-Name header, percent-encoded.');
        }
        $name = trim(rawurldecode($header));
        if (!mb_check_encoding($name, 'UTF-8') || preg_match('/[\p{Cc}\x{202A}-\x{202E}\x{2066}-\x{2069}\/\\\\]/u', $name)) {
            throw new HttpError(400, "File names can't contain slashes or control characters.");
        }
        if (strlen($name) > self::MAX_NAME_BYTES) {
            throw new HttpError(400, 'File names can be at most ' . self::MAX_NAME_BYTES . ' bytes long.');
        }
        $ext = preg_match('/.\.([A-Za-z]+)$/', $name, $m) ? strtolower($m[1]) : '';
        $format = self::FORMATS[$ext] ?? throw new HttpError(400, 'File names need a name and one of these extensions: .' . implode(', .', array_keys(self::FORMATS)) . '.');
        return [$name, $format];
    }

    public function list(): array
    {
        $statement = $this->db->prepare('SELECT ' . self::FIELDS . ' FROM files WHERE user_id = ? ORDER BY updated_at DESC, id');
        $statement->execute([$this->user->id]);
        return $statement->fetchAll();
    }

    public function get(string $id): array
    {
        $statement = $this->db->prepare('SELECT ' . self::FIELDS . ' FROM files WHERE id = ? AND user_id = ?');
        $statement->execute([$id, $this->user->id]);
        return $statement->fetch() ?: throw new HttpError(404, 'No such file.');
    }

    public function path(string $id): string
    {
        // Routes only match 32 hex characters; this is the last line of defence for the filesystem
        if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
            throw new \LogicException('Invalid file ID reached the store');
        }
        return Config::DATA_DIR . "/files/{$id}";
    }

    // A stored file's contents, decrypted chunk by chunk. The whole file is authenticated before the first
    // chunk comes out, so a damaged file is an error up front, never part of a download.
    /** @return \Generator<string> */
    public function read(string $id): \Generator
    {
        $file = fopen($this->path($id), 'rb') ?: throw new \RuntimeException("Can't open stored file {$id}");
        try {
            foreach (Vault::decrypt($file, $this->user->fileKey, $id) as $_) {
                // First pass: check every chunk, release nothing
            }
            // Same handle, so it's the same file even if an update replaces it in between
            rewind($file);
            yield from Vault::decrypt($file, $this->user->fileKey, $id);
        } finally {
            fclose($file);
        }
    }

    public function create(string $name, string $format, int $length): array
    {
        // The ID is part of what's encrypted, so it's chosen before the upload is read
        $id = bin2hex(random_bytes(16));
        $tmp = $this->receive($id, $format, $length);
        try {
            $this->transaction(function () use ($id, $name, $format, $length, $tmp): void {
                $this->checkQuota(1, $length);
                $now = self::now();
                $this->db->prepare('INSERT INTO files (id, user_id, name, format, size, rev, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)')
                    ->execute([$id, $this->user->id, $name, $format, $length, $now, $now]);
                $this->moveInto($tmp, $id);
            });
            return $this->get($id);
        } finally {
            if (is_file($tmp)) {
                unlink($tmp);
            }
        }
    }

    // Replaces a file's contents (and optionally its name), if it's still at the revision the client read
    /** @param array{string, string}|null $rename [name, format] */
    public function update(string $id, int $rev, ?array $rename, int $length): array
    {
        $current = $this->get($id);
        [$name, $format] = $rename ?? [$current['name'], $current['format']];
        $tmp = $this->receive($id, $format, $length);
        try {
            $this->transaction(function () use ($id, $rev, $name, $format, $length, $tmp): void {
                $old = $this->get($id);
                self::checkRevision($old, $rev);
                $this->checkQuota(0, $length - $old['size']);
                $this->db->prepare('UPDATE files SET name = ?, format = ?, size = ?, rev = rev + 1, updated_at = ? WHERE id = ? AND user_id = ?')
                    ->execute([$name, $format, $length, self::now(), $id, $this->user->id]);
                $this->moveInto($tmp, $id);
            });
            return $this->get($id);
        } finally {
            if (is_file($tmp)) {
                unlink($tmp);
            }
        }
    }

    public function delete(string $id, int $rev): void
    {
        $this->transaction(function () use ($id, $rev): void {
            self::checkRevision($this->get($id), $rev);
            $this->db->prepare('DELETE FROM files WHERE id = ? AND user_id = ?')->execute([$id, $this->user->id]);
        });
        unlink($this->path($id));
    }

    // Encrypts the request body into a temporary file in /data as it arrives, so a large upload never sits
    // in memory and its plaintext never reaches the disk
    private function receive(string $id, string $format, int $length): string
    {
        $tmp = Config::DATA_DIR . '/tmp/' . bin2hex(random_bytes(16));
        $out = fopen($tmp, 'xb') ?: throw new \RuntimeException("Can't create {$tmp}");
        try {
            Vault::encrypt(fopen('php://input', 'rb'), $out, $length, $this->user->fileKey, $id, function (string $head) use ($format): void {
                if (!self::looksLike($format, $head)) {
                    throw new HttpError(415, "The file's contents don't match its .{$format} extension.");
                }
            });
            fsync($out);
            fclose($out);
            return $tmp;
        } catch (\Throwable $e) {
            if (is_resource($out)) {
                fclose($out);
            }
            unlink($tmp);
            throw $e;
        }
    }

    // A sanity check of the first bytes. The server never reads documents beyond this.
    private static function looksLike(string $format, string $head): bool
    {
        return match ($format) {
            'docx', 'odt' => str_starts_with($head, "PK\x03\x04"),
            'wurd' => (bool) preg_match('/^\s*\{\s*"wurd"\s*:\s*"encrypted-document"/', $head),
            // A real Word 97 file, or the HTML, RTF or MHT text that also goes by .doc
            'doc' => str_starts_with($head, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") || !str_contains($head, "\0"),
            'html', 'txt' => true,
        };
    }

    private function moveInto(string $tmp, string $id): void
    {
        if (!rename($tmp, $this->path($id))) {
            throw new \RuntimeException("Can't store file {$id}");
        }
    }

    private static function checkRevision(array $file, int $rev): void
    {
        if ($file['rev'] !== $rev) {
            throw new HttpError(412, 'The file was changed somewhere else since you opened it.', ['ETag' => "\"{$file['rev']}\""]);
        }
    }

    private function checkQuota(int $addFiles, int $addBytes): void
    {
        [$files, $bytes] = $this->db->query('SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files')->fetch(\PDO::FETCH_NUM);
        if ($files + $addFiles > $this->config->maxFiles) {
            throw new HttpError(507, "The server is full: it holds at most {$this->config->maxFiles} files.");
        }
        if ($bytes + $addBytes > $this->config->maxTotalBytes) {
            throw new HttpError(507, 'The server is full: its storage limit has been reached.');
        }
    }

    // Writes happen one at a time (BEGIN IMMEDIATE), so the revision check and the write can't interleave
    private function transaction(callable $fn): void
    {
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $fn();
            $this->db->exec('COMMIT');
        } catch (\Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
    }

    public static function now(): string
    {
        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
    }
}
