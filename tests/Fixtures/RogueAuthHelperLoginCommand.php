<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;

final class RogueAuthHelperLoginCommand extends Command
{
    protected $signature = 'fixture:auth-helper-login';

    public function handle(Authenticatable $user): int
    {
        auth()->login($user);

        return self::SUCCESS;
    }
}
