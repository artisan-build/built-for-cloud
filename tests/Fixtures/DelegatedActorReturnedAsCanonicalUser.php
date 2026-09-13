<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Auth\Authenticatable;

abstract class DelegatedActorReturnedAsCanonicalUser
{
    abstract public function userFor(DelegatedActor $actor): User;

    abstract public function authenticatableFor(DelegatedActor $actor): Authenticatable;

    abstract public function userOrFalseFor(DelegatedActor $actor): User|false;
}
