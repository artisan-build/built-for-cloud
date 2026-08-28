<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand;
use ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand;
use ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenListCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRevokeSelfCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand;
use ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresDurableStore;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Listeners\QueueOwnershipWebhook;
use Illuminate\Auth\AuthManager;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

final class BuiltForCloudServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/built-for-cloud.php', 'built-for-cloud');

        $this->app->singleton(UsageReporter::class, NullUsageReporter::class);

        // The seam (PRD 1.0): exchange mints durables through this binding
        // only. `api_tokens` stays the default; an app's declaration opts
        // into the unified store at rebuild time (DeclaresDurableStore).
        $this->app->bind(DurableCredentialMinter::class, function (Application $app): DurableCredentialMinter {
            $declaration = $app->make(CredentialDeclaration::class);

            if ($declaration instanceof DeclaresDurableStore
                && $declaration->durableCredentialStore() === DurableStore::Credentials) {
                return $app->make(UnifiedStoreCredentialMinter::class);
            }

            return $app->make(ApiTokenMinter::class);
        });

        $this->app->bind(CredentialDeclaration::class, function (Application $app): CredentialDeclaration {
            /** @var class-string<CredentialDeclaration> $declaration */
            $declaration = config('built-for-cloud.credentials.declaration') ?? DefaultCredentialDeclaration::class;

            /** @var CredentialDeclaration */
            return $app->make($declaration);
        });
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        Event::listen(OwnershipReleasePending::class, QueueOwnershipWebhook::class);
        Event::listen(OwnershipTransferred::class, QueueOwnershipWebhook::class);

        $this->registerRateLimiters();

        Auth::resolved(function (AuthManager $auth): void {
            $auth->extend('bfc', function (Application $app, string $name, array $config): CredentialGuard {
                /** @var array<string, mixed> $config */
                return new CredentialGuard($app, $name, $config);
            });
        });

        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app['router'];

            $router->aliasMiddleware('bfc.auth', EnsureUserIsAuthenticated::class);
            $router->aliasMiddleware('bfc.admin', EnsureUserIsAdmin::class);
            $router->aliasMiddleware('bfc.token.admin', EnsureAdminToken::class);
            $router->aliasMiddleware('bfc.ability', EnsureCredentialAbility::class);

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

            // The unified store's verb routes (PRD 1.0): the HTTP half of
            // the two-transport rule, at a FIXED /bfc/ path like every
            // other package surface (PRD 1.12's precedent) — part of the
            // versioned public contract (docs/http-contract.md).
            $router->get('/bfc/credentials', [ManageCredentials::class, 'index'])
                ->middleware('bfc.token.admin');

            $router->post('/bfc/credentials', [ManageCredentials::class, 'store'])
                ->middleware('bfc.token.admin');

            $router->delete('/bfc/credentials/{id}', [ManageCredentials::class, 'destroy'])
                ->middleware('bfc.token.admin');

            if ((bool) config('built-for-cloud.credential_api.enabled', false)) {
                $router->prefix(trim((string) config('built-for-cloud.credential_api.prefix', 'api/credentials'), '/'))
                    ->middleware('bfc.token.admin')
                    ->group(function (Router $router): void {
                        $router->get('/', [ManageTokens::class, 'index']);
                        $router->get('/client-observations', ClientObservations::class);
                        $router->post('/', [ManageTokens::class, 'store']);
                        // The precise verb rides its own two-segment path, so
                        // it can never collide with the one-segment name route
                        // below — a token literally named "id" still deletes
                        // by name.
                        $router->delete('/id/{id}', [ManageTokens::class, 'destroyById']);
                        $router->delete('/{name}', [ManageTokens::class, 'destroy']);
                    });
            }
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                CreateAdminCommand::class,
                CredentialListCommand::class,
                CredentialMintCommand::class,
                CredentialRevokeCommand::class,
                FallbackTokenGenerateCommand::class,
                InstallOperatorCredentialCommand::class,
                OutboxDrainCommand::class,
                OwnershipMintClaimCommand::class,
                OwnershipRemintOwnerTokenCommand::class,
                TokenCreateCommand::class,
                TokenListCommand::class,
                TokenRevokeCommand::class,
                TokenRevokeSelfCommand::class,
                TokenRotateCommand::class,
                TokenUsageCommand::class,
                WarnExpiringCredentialsCommand::class,
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
