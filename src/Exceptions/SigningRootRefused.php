<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class SigningRootRefused extends RuntimeException
{
    public static function unavailable(): self
    {
        return new self('Exactly one valid current installation signing root is required.');
    }

    public static function alreadyProvisioned(): self
    {
        return new self('A current installation signing root already exists. Rotate it instead.');
    }

    public static function dedicatedLifecycleOnly(): self
    {
        return new self('The installation signing root is reserved for its dedicated lifecycle.');
    }
}
