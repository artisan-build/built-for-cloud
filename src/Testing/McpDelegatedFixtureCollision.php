<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RuntimeException;

/** @internal */
final class McpDelegatedFixtureCollision extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('The delegated enforcement fixture collided with pre-existing test state.');
    }
}
