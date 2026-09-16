<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Actions\PruneCredentialAuthorizations;
use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;

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

    public function registerCredentialAuthorizationPrune(mixed $schedule): void
    {
        if (! $schedule instanceof Schedule) {
            throw new InvalidArgumentException('Credential authorization pruning requires the Laravel scheduler.');
        }

        $this->call($schedule, PruneCredentialAuthorizations::class)
            ->hourly()
            ->name('bfc-credential-authorizations-prune');
    }
}
