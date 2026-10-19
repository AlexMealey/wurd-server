<?php
// Encryption at rest. A stored file is a libsodium secretstream (XChaCha20-Poly1305): a header, then
// 64 KiB chunks, each authenticated together with the file's ID so one file can't be swapped for another.
// The key comes from the owner's token (see Users), so plaintext only exists in memory, during a request
// made with that token.
declare(strict_types=1);

namespace Wurd;

final class Vault
{
    private const int CHUNK_BYTES = 65536;
    // How much of the plaintext the format check sees
    private const int HEAD_BYTES = 8192;

    // Encrypts exactly $length bytes from $in into $out. $checkHead sees the first plaintext bytes and
    // throws to refuse the file.
    /**
     * @param resource $in
     * @param resource $out
     * @param callable(string): void $checkHead
     */
    public static function encrypt($in, $out, int $length, string $key, string $id, callable $checkHead): void
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        self::write($out, $header);
        $left = $length;
        $first = true;
        // Runs at least once, so an empty file still gets its final chunk
        do {
            $want = min(self::CHUNK_BYTES, $left);
            $chunk = self::read($in, $want);
            if (strlen($chunk) !== $want) {
                throw new HttpError(400, 'The upload ended early.');
            }
            if ($first) {
                $checkHead(substr($chunk, 0, self::HEAD_BYTES));
                $first = false;
            }
            $left -= $want;
            $tag = $left === 0 ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            self::write($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, $id, $tag));
        } while ($left > 0);
    }

    // The plaintext of a stored file, chunk by chunk. Throws if the key is wrong or the file was changed, cut short
    // or added to. Each chunk is authenticated before it's yielded; Store::read checks them all before sending any.
    /**
     * @param resource $in
     * @return \Generator<string>
     */
    public static function decrypt($in, string $key, string $id): \Generator
    {
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(self::read($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES), $key);
        do {
            $sealed = self::read($in, self::CHUNK_BYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $sealed, $id);
            if ($result === false) {
                throw new \RuntimeException("Stored file {$id} failed to decrypt: wrong key, or the file is damaged");
            }
            [$chunk, $tag] = $result;
            yield $chunk;
        } while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
        if (self::read($in, 1) !== '') {
            throw new \RuntimeException("Stored file {$id} has data after its final chunk");
        }
    }

    // Reads up to $length bytes, fewer only at the end of the stream (php://input can return short reads)
    /** @param resource $in */
    private static function read($in, int $length): string
    {
        $data = '';
        while (strlen($data) < $length && !feof($in)) {
            $more = fread($in, $length - strlen($data));
            if ($more === false || $more === '') {
                break;
            }
            $data .= $more;
        }
        return $data;
    }

    /** @param resource $out */
    private static function write($out, string $data): void
    {
        if (fwrite($out, $data) !== strlen($data)) {
            throw new \RuntimeException("Can't write an encrypted file");
        }
    }
}
