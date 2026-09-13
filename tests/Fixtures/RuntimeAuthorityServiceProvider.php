<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;

final class RuntimeAuthorityServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->commands([
            RuntimeAuthorityCommand::class,
            HostRuntimeAuthCommand::class,
        ]);
    }
}
