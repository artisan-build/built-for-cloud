<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class InvalidInvitation extends RuntimeException
{
    public static function forToken(string $token): self
    {
        return new self("Invitation [{$token}] is invalid, expired, or already accepted.");
    }
}
