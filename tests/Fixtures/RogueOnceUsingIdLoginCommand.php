<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

final class RogueOnceUsingIdLoginCommand extends Command
{
    protected $signature = 'fixture:rogue-once-using-id';

    public function handle(Authenticatable $user): int
    {
        Auth::onceUsingId(1);

        return self::SUCCESS;
    }
}
