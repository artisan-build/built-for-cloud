<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * A stored hmac ciphertext cannot be read: its key-version names no key in
 * the read-keyring (the old APP_KEY was dropped from APP_PREVIOUS_KEYS
 * before the rewrap verified zero old-version rows), or the row predates
 * version stamping. The message names the version, never any key or
 * ciphertext material.
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
}
