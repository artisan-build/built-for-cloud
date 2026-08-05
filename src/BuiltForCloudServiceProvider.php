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
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Illuminate\Routing\Router;
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
            /** @var Router $router */
            $router = $this->app['router'];

            $router->aliasMiddleware('bfc.auth', EnsureUserIsAuthenticated::class);
            $router->aliasMiddleware('bfc.admin', EnsureUserIsAdmin::class);
            $router->aliasMiddleware('bfc.token.admin', EnsureAdminToken::class);

            $router->get('/bfc/meta', MetaController::class)
                ->middleware('throttle:60,1');

            $router->post('/bfc/ownership/claim', [ManageOwnership::class, 'claim'])
                ->middleware('throttle:10,1');

            $router->post('/bfc/ownership/release', [ManageOwnership::class, 'release'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/ownership/cancel-transfer', [ManageOwnership::class, 'cancelTransfer'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/onboarding/issue', [ManageOnboarding::class, 'issue'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/onboarding/exchange', [ManageOnboarding::class, 'exchange'])
                ->middleware('throttle:10,1');

            $router->post('/bfc/onboarding/verify', [ManageOnboarding::class, 'verify'])
                ->middleware('throttle:60,1');

            if ((bool) config('built-for-cloud.credential_api.enabled', false)) {
                $router->prefix(trim((string) config('built-for-cloud.credential_api.prefix', 'api/credentials'), '/'))
                    ->middleware('bfc.token.admin')
                    ->group(function (Router $router): void {
                        $router->get('/', [ManageTokens::class, 'index']);
                        $router->post('/', [ManageTokens::class, 'store']);
                        $router->delete('/{name}', [ManageTokens::class, 'destroy']);
                    });
            }
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
