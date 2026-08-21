<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenListCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Listeners\QueueOwnershipWebhook;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
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

        Event::listen(OwnershipReleasePending::class, QueueOwnershipWebhook::class);
        Event::listen(OwnershipTransferred::class, QueueOwnershipWebhook::class);

        $this->registerRateLimiters();

        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app['router'];

            $router->aliasMiddleware('bfc.auth', EnsureUserIsAuthenticated::class);
            $router->aliasMiddleware('bfc.admin', EnsureUserIsAdmin::class);
            $router->aliasMiddleware('bfc.token.admin', EnsureAdminToken::class);

            $router->get('/bfc/meta', MetaController::class)
                ->middleware('throttle:bfc-public');

            $router->post('/bfc/ownership/claim', [ManageOwnership::class, 'claim'])
                ->middleware('throttle:bfc-claim');

            $router->post('/bfc/ownership/release', [ManageOwnership::class, 'release'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/ownership/cancel-transfer', [ManageOwnership::class, 'cancelTransfer'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/onboarding/issue', [ManageOnboarding::class, 'issue'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/onboarding/exchange', [ManageOnboarding::class, 'exchange'])
                ->middleware('throttle:bfc-claim');

            $router->post('/bfc/onboarding/verify', [ManageOnboarding::class, 'verify'])
                ->middleware('throttle:bfc-public');

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
                OwnershipMintClaimCommand::class,
                OwnershipRemintOwnerTokenCommand::class,
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

    /**
     * BfC's management routes are public/pre-auth, and a headless app may have
     * no auth guard at all (`auth.defaults.guard` null, `auth.guards` empty).
     * Laravel's inline `throttle:N,1` builds its signature via
     * `$request->user()`, so on such an app the AuthManager throws and every
     * throttled route 500s. Keying these limiters on the IP is both correct for
     * pre-auth traffic and free of any guard resolution.
     */
    private function registerRateLimiters(): void
    {
        RateLimiter::for('bfc-public', fn (Request $request): Limit => Limit::perMinute(60)->by($request->ip() ?? 'unknown'));

        RateLimiter::for('bfc-claim', fn (Request $request): Limit => Limit::perMinute(10)->by($request->ip() ?? 'unknown'));
    }
}
