<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Tests\PublicSurfaceScan;

/**
 * The escape {@see PublicSurfaceScan}
 * exists to name: a class with a private writer and a SECOND public
 * method that reaches it, added by someone who did not touch the file
 * list or any method name a fixed-list test happened to know about.
 *
 * It is the shape of the scenario, not a copy of the guard — the scan is
 * generic over class names, so a fixture is enough to prove the walk can
 * fail.
 */
final class SurfaceWithExtraPublicMethod
{
    public function redeem(string $token): void
    {
        $this->beginSession($token);
    }

    /** The one that must be NAMED. */
    public function enterFromTrustedSource(string $claims): void
    {
        $this->beginSession($claims);
    }

    private function beginSession(string $state): void
    {
        // Stands in for the real writer; writes nothing.
    }
}
