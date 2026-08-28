<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;
use Throwable;

/**
 * A stored hmac ciphertext cannot be read: its key-version names no key in
 * the read-keyring (the old APP_KEY was dropped from APP_PREVIOUS_KEYS
 * before the rewrap verified zero old-version rows), the row predates
 * version stamping, or the ring itself cannot serve the read (an
 * unsupported cipher, a wrong-length or absent key, a malformed ring
 * entry, a corrupted payload — {@see ringFailure}). The message names the
 * version, never any key or ciphertext material.
 */
final class HmacKeyUnreadable extends RuntimeException
{
    public static function unknownVersion(string $keyVersion): self
    {
        return new self(sprintf(
            'No key in the read-keyring carries version %s. Restore the old key to APP_PREVIOUS_KEYS and '
            .'run bfc:hmac:rewrap to completion before dropping keys from the ring.',
            $keyVersion,
        ));
    }

    public static function missingVersion(): self
    {
        return new self(
            'This hmac ciphertext carries no encryption key-version; it cannot be attributed to any ring key.',
        );
    }

    /**
     * The catch-all for a ring that cannot serve a read (rework Fix 3):
     * an unsupported cipher, a wrong-length or absent key, a malformed
     * base64 ring entry, a corrupted or MAC-invalid payload. Generic on
     * purpose — the caller-facing message names the version and nothing
     * about the ring's contents; the underlying failure rides as
     * `previous` for operator diagnostics.
     */
    public static function ringFailure(string $keyVersion, Throwable $previous): self
    {
        return new self(
            sprintf(
                'The hmac ciphertext under key-version %s could not be read: the ring key or the payload is '
                .'unusable (wrong key length, unsupported cipher, malformed ring entry, or corrupted ciphertext). '
                .'Check APP_KEY / APP_PREVIOUS_KEYS and app.cipher.',
                $keyVersion,
            ),
            previous: $previous,
        );
    }
}
