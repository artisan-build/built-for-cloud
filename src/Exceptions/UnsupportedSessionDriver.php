<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class UnsupportedSessionDriver extends RuntimeException
{
    public const string DATABASE_MESSAGE = 'Built for Cloud found the unsupported "database" session driver. '
        .'Laravel Cloud injects "cookie" by default; "redis" is the recommended step up when a more robust session store is needed. '
        .'Database sessions are intended for local development and hobby sites.';

    public static function database(): self
    {
        return new self(self::DATABASE_MESSAGE);
    }
}
