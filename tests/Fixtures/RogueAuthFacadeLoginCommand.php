<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

final class RogueAuthFacadeLoginCommand extends Command
{
    protected $signature = 'fixture:auth-facade-login';

    public function handle(Authenticatable $user): int
    {
        Auth::login($user);

        return self::SUCCESS;
    }
}
