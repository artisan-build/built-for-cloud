<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Command;

final class RogueRoleExistsCommand extends Command
{
    protected $signature = 'fixture:role-exists {--as=}';

    public function handle(): int
    {
        abort_unless(User::query()->where([
            'role' => UserRole::Owner->value,
            'email' => $this->option('as'),
        ])->exists(), self::FAILURE);

        return self::SUCCESS;
    }
}
