<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;

final class RogueAttemptLoginCommand extends Command
{
    protected $signature = 'fixture:rogue-attempt-login';

    public function handle(Authenticatable $user): int
    {
        Auth::attempt(['email' => 'rogue@example.test', 'password' => 'rogue']);

        return self::SUCCESS;
    }
}
