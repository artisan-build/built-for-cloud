<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Command;

final class RogueUserRoleCommand extends Command
{
    protected $signature = 'fixture:rogue-user-role';

    public function handle(): int
    {
        return in_array('owner', [UserRole::Owner->value], true) ? self::SUCCESS : self::FAILURE;
    }
}
