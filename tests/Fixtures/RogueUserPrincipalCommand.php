<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Auth;

final class RogueUserPrincipalCommand extends Command
{
    protected $signature = 'fixture:rogue-user-principal';

    public function handle(): int
    {
        $user = User::query()->first();
        Auth::login($user);

        return self::SUCCESS;
    }
}
