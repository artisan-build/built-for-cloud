<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Command;

final class UserWritingInstallCommand extends Command
{
    protected $signature = 'fixture:user-writing-install';

    public function handle(): int
    {
        $ownerExists = User::query()->where('role', UserRole::Owner->value)->exists();
        $user = new User;
        $user->forceFill([
            'name' => 'Fixture install user',
            'email' => 'fixture-install@example.test',
            'role' => $ownerExists ? UserRole::Admin->value : UserRole::Owner->value,
        ])->save();

        return self::SUCCESS;
    }
}
