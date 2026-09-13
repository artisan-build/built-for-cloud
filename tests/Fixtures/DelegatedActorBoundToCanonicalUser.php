<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\User;

final class DelegatedActorBoundToCanonicalUser
{
    /** @var array<string, User> */
    private array $usersByActor = [];

    public function bind(DelegatedActor $actor, User $user): void
    {
        $this->usersByActor[$actor->getAuthIdentifier()] = $user;
    }
}
