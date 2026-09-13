<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use LogicException;

final class SystemAuthorityViolation extends LogicException
{
    public static function humanAuthentication(): self
    {
        return new self('A Built for Cloud system-authority entry cannot authenticate a human.');
    }

    public static function boundUserActor(): self
    {
        return new self('A Built for Cloud system-authority entry cannot synthesize a bound-user audit actor.');
    }
}
