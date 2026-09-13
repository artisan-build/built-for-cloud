<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

final class RogueAuthGuardLoginCommand extends Command
{
    protected $signature = 'fixture:auth-guard-login';

    public function handle(Authenticatable $user): int
    {
        Auth::guard('web')->login($user);

        return self::SUCCESS;
    }
}
