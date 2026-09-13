<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\Auth;

final class RuntimeIndirectAuthenticator
{
    public function login(User $user): void
    {
        Auth::login($user);
    }
}
