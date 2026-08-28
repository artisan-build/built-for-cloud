<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialActivateCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand;
use ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand;
use ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand;
use ArtisanBuild\BuiltForCloud\Commands\InvitationIssueCommand;
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
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
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
        // Surface selection (PRD 1.14, fleet F2): each family below is
        // mounted only when its `built-for-cloud.surfaces.*` key says so
        // — whole families, never single routes (the claim surfaces are
        // deliberately not env-gatable one by one, PRD 1.12). Everything
        // defaults ON. The guard driver, rate limiters, middleware
        // aliases, and config publishing are not surfaces: they mount
        // nothing and an app with routes off still uses them for its own
        // routes.
        if ($this->surfaceEnabled('migrations')) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if ($this->surfaceEnabled('listeners')) {
            Event::listen(OwnershipReleasePending::class, QueueOwnershipWebhook::class);
            Event::listen(OwnershipTransferred::class, QueueOwnershipWebhook::class);
        }

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
            $router->aliasMiddleware('bfc.credential.admin', EnsureCredentialAdmin::class);
            $router->aliasMiddleware('bfc.ability', EnsureCredentialAbility::class);
            // The verify half of the hmac pair (PRD 1.21, SEC-V3-07):
            // consuming apps put it in front of signed-message routes.
            $router->aliasMiddleware('bfc.hmac', VerifyHmacSignature::class);

            if ($this->surfaceEnabled('routes')) {
                $this->mountRoutes($router);
            }
        }

        if ($this->app->runningInConsole()) {
            if ($this->surfaceEnabled('commands')) {
                $this->registerCommands();
            }

            $this->publishes([
                __DIR__.'/../config/built-for-cloud.php' => $this->app->configPath('built-for-cloud.php'),
            ], 'built-for-cloud-config');
        }
    }

    private function surfaceEnabled(string $surface): bool
    {
        return (bool) config('built-for-cloud.surfaces.'.$surface, true);
    }

    /**
     * The HTTP surface family (PRD 1.14): mounted whole, or not at all.
     */
    private function mountRoutes(Router $router): void
    {
        $router->get('/bfc/meta', MetaController::class)
            ->middleware('throttle:bfc-public');

        $router->post('/bfc/ownership/claim', [ManageOwnership::class, 'claim'])
            ->middleware('throttle:bfc-claim');

        $router->post('/bfc/ownership/release', [ManageOwnership::class, 'release'])
            ->middleware('bfc.token.admin');

        $router->post('/bfc/ownership/cancel-transfer', [ManageOwnership::class, 'cancelTransfer'])
            ->middleware('bfc.token.admin');

        // The hitch claim-contract route (PRD 1.12 / OSS-8): the wire
        // face of hitch/docs/claim-contract.md over the same claim
        // primitive as the onboarding exchange. Unconditional at a
        // FIXED path like every /bfc/* surface — never behind a
        // configurable prefix, never behind its own env flag.
        $router->post('/bfc/claim', [ManageOnboarding::class, 'claim'])
            ->middleware('throttle:bfc-claim');

        $router->post('/bfc/onboarding/issue', [ManageOnboarding::class, 'issue'])
            ->middleware('bfc.token.admin');

        $router->post('/bfc/onboarding/exchange', [ManageOnboarding::class, 'exchange'])
            ->middleware('throttle:bfc-claim');

        $router->post('/bfc/onboarding/verify', [ManageOnboarding::class, 'verify'])
            ->middleware('throttle:bfc-public');

        // The unified store's verb routes (PRD 1.0): the HTTP half of
        // the two-transport rule, at a FIXED /bfc/ path like every
        // other package surface (PRD 1.12's precedent) — part of the
        // versioned public contract (docs/http-contract.md). Their gate
        // accepts a legacy admin token OR the installer-minted operator
        // credential (PRD 1.20 — the credential must work on the
        // surface it exists to manage), and each route names its
        // verb-family ability (GATE-3.7 least privilege): the
        // admin-equivalent `credential:admin` satisfies every one, a
        // narrower operator credential only its own family. Write and
        // expensive verbs additionally carry the per-operator-
        // credential + per-IP rate limiter (throttle FIRST, so even
        // failing auth attempts are bounded).
        $router->get('/bfc/credentials', [ManageCredentials::class, 'index'])
            ->middleware('bfc.credential.admin:'.OperatorAbility::CredentialRead->value);

        $router->post('/bfc/credentials', [ManageCredentials::class, 'store'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialMint->value]);

        $router->delete('/bfc/credentials/{id}', [ManageCredentials::class, 'destroy'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialRevoke->value]);

        $router->post('/bfc/credentials/{id}/rotate', [ManageCredentials::class, 'rotate'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialRotate->value]);

        // The hmac signing cutover (PRD 1.21, SEC-V3-01): a separate
        // operator-authorized verb — the claim exchange delivers and
        // never activates, so the flip needs its own route. Its
        // operator ability is the rotate FAMILY (activation completes
        // rotation's dance); the declaration matrix's own `activate`
        // verb stays the finer split.
        $router->post('/bfc/credentials/{id}/activate', [ManageCredentials::class, 'activate'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialRotate->value]);

        // The machine-callable invite verb (PRD 1.13, SEC-V3-05): the
        // HTTP half of its two transports, behind the same operator
        // gate as the unified verb routes — an integration triggers
        // the INVITATION, never a key mint. Its family is `mint` (an
        // invitation is a minted claim code).
        $router->post('/bfc/invitations', [ManageInvitations::class, 'store'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialMint->value]);

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
                    // Rotation's primary verb on this store too (PRD
                    // 1.7): by id, on the same collision-proof path.
                    $router->post('/id/{id}/rotate', [ManageTokens::class, 'rotateById']);
                    $router->delete('/{name}', [ManageTokens::class, 'destroy']);
                });
        }
    }

    /**
     * The artisan command family (PRD 1.14).
     */
    private function registerCommands(): void
    {
        $this->commands([
            CreateAdminCommand::class,
            CredentialActivateCommand::class,
            CredentialListCommand::class,
            CredentialMintCommand::class,
            CredentialRevokeCommand::class,
            CredentialRotateCommand::class,
            FallbackTokenGenerateCommand::class,
            HmacRewrapCommand::class,
            InstallOperatorCredentialCommand::class,
            InvitationIssueCommand::class,
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

        // GATE-3.7: write and expensive operator verbs are limited per
        // operator credential + IP, under a global ceiling. The
        // per-credential key is the sha256 of the presented bearer (the
        // limiter runs before the gate resolves a row id, and the digest
        // identifies the credential without persisting its plaintext —
        // the same at-rest form the stores use); missing bearers share
        // one bucket per IP, so failed-auth hammering is bounded too.
        RateLimiter::for('bfc-operator-write', function (Request $request): array {
            $bearer = $request->bearerToken();
            $credentialKey = $bearer === null || $bearer === '' ? 'anonymous' : hash('sha256', $bearer);

            return [
                Limit::perMinute(60)->by($credentialKey.'|'.($request->ip() ?? 'unknown')),
                Limit::perMinute(600)->by('bfc-operator-write-global'),
            ];
        });
    }
}
