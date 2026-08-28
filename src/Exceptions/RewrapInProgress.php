<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * An APP_KEY rewrap of the hmac store is in progress (SEC-V3-08): some
 * hmac ciphertext still carries a non-primary encryption key-version.
 * hmac activation and rotation PAUSE during the cutover — both write or
 * cut over key material, and interleaving them with a half-finished
 * re-encryption sweep is how rows fossilize under dropped keys. The
 * retry-later message names the command that finishes the cutover.
 */
final class RewrapInProgress extends RuntimeException
{
    public static function refusing(string $verb): self
    {
        return new self(sprintf(
            'An APP_KEY rewrap of the hmac store is in progress (rows still carry an old encryption '
            .'key-version), so hmac %s is paused. Run bfc:hmac:rewrap to completion — it verifies zero '
            .'old-version rows — then retry.',
            $verb,
        ));
    }
}
