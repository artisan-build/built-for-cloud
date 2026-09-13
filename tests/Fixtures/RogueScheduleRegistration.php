<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Scheduling\Schedule;

final class RogueScheduleRegistration
{
    public function schedule(Schedule $schedule): void
    {
        $schedule->call(static fn (): bool => UserRole::Owner === UserRole::Owner);
    }
}
