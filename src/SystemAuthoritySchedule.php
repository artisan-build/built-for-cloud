<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;

/** Registers package schedule callbacks inside the system-authority context. */
final readonly class SystemAuthoritySchedule
{
    public function __construct(
        private SystemAuthorityContext $context,
        private Container $container,
    ) {}

    /**
     * @param  array<string, mixed>  $parameters
     */
    public function call(Schedule $schedule, callable|string $callback, array $parameters = []): CallbackEvent
    {
        return $schedule->call(
            fn (): mixed => $this->context->run(
                fn (): mixed => $this->container->call($callback, $parameters),
            ),
        );
    }
}
