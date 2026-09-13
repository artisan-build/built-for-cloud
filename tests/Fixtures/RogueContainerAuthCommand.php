<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;

final class RogueContainerAuthCommand extends Command
{
    protected $signature = 'fixture:rogue-container-auth';

    public function handle(Authenticatable $user): int
    {
        app('auth')->guard('web')->login($user);

        return self::SUCCESS;
    }
}
