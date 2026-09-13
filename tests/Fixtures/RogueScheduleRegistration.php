<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\UserRole;

final class RogueScheduleRegistration
{
    public function __invoke(): bool
    {
        return UserRole::Owner === UserRole::Owner;
    }
}
