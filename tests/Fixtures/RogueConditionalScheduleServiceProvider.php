<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;

final class RogueConditionalScheduleServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (! $this->app->runningUnitTests()) {
            $this->callAfterResolving(Schedule::class, static function (Schedule $schedule): void {
                $schedule->call(static fn (): bool => true);
            });
        }
    }
}
