<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class SigningRootRefused extends RuntimeException
{
    public static function unavailable(): self
    {
        return new self('Exactly one current signing root is required.');
    }

    public static function alreadyProvisioned(): self
    {
        return new self('A current signing root already exists. Rotate it instead.');
    }
}
