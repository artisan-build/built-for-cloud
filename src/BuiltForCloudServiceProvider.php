<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenListCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Illuminate\Support\ServiceProvider;

final class BuiltForCloudServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/built-for-cloud.php', 'built-for-cloud');

        $this->app->singleton(UsageReporter::class, NullUsageReporter::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->bound('router')) {
            $this->app['router']->aliasMiddleware('bfc.auth', EnsureUserIsAuthenticated::class);
            $this->app['router']->aliasMiddleware('bfc.admin', EnsureUserIsAdmin::class);
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                CreateAdminCommand::class,
                FallbackTokenGenerateCommand::class,
                TokenCreateCommand::class,
                TokenListCommand::class,
                TokenRevokeCommand::class,
                TokenRotateCommand::class,
                TokenUsageCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/built-for-cloud.php' => $this->app->configPath('built-for-cloud.php'),
            ], 'built-for-cloud-config');
        }
    }
}
