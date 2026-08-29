<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand;
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
use ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand;
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
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\Listeners\QueueOwnershipWebhook;
use Illuminate\Auth\AuthManager;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Throwable;

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

        // The personal-credentials surface (PRD 1.17): the SAME verbs
        // above, session-authenticated and scoped to the caller's OWN
        // credentials. Its gate is the session, not an operator ability
        // — the app supplies the authenticated human — and the subject
        // is derived SERVER-SIDE from that session by the app's
        // declaration (SEC-V3-07), never from anything in the request.
        // `bfc.auth` runs the offboarding kill too, so an offboarded
        // user's surviving session cannot reach the screen (PRD 1.15).
        // Fixed `/bfc/` path, part of the routes family, like every
        // other package surface.
        //
        // These are BROWSER routes, and the only ones the package mounts
        // (rework Fix 1). Every other /bfc/* surface is a token API that
        // wants no session; these three ride the full session stack —
        // see personalSessionMiddleware() — so cookie sessions actually
        // start, and so the MUTATING verbs are CSRF-protected. Without
        // it a session-riding forgery on a logged-in user's browser
        // could mint or revoke their credentials.
        $personal = $this->personalSessionMiddleware($router);

        $router->get('/bfc/me/credentials', [PersonalCredentials::class, 'index'])
            ->middleware(['throttle:bfc-personal', ...$personal, 'bfc.auth']);

        $router->post('/bfc/me/credentials', [PersonalCredentials::class, 'store'])
            ->middleware(['throttle:bfc-personal', ...$personal, 'bfc.auth']);

        $router->delete('/bfc/me/credentials/{id}', [PersonalCredentials::class, 'destroy'])
            ->middleware(['throttle:bfc-personal', ...$personal, 'bfc.auth']);

        // The machine-callable invite verb (PRD 1.13, SEC-V3-05): the
        // HTTP half of its two transports, behind the same operator
        // gate as the unified verb routes — an integration triggers
        // the INVITATION, never a key mint. Its family is `mint` (an
        // invitation is a minted claim code).
        $router->post('/bfc/invitations', [ManageInvitations::class, 'store'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::CredentialMint->value]);

        // The console re-key verb (Console PRD D12): the retrofit path
        // that files a countersigning key onto an ALREADY-CLAIMED
        // deployment without re-onboarding it. Fixed path under the
        // `/bfc/console/*` namespace the contract reserved for exactly
        // this, in the routes family like every other package surface.
        //
        // Its stack, outermost first, and each layer is load-bearing:
        //
        //  1. `throttle:bfc-operator-write` — bounded before anything
        //     else runs, so refused attempts cost budget too;
        //  2. `UniformConsoleKeyRefusal` — collapses the gate's 401/403
        //     split into ONE external answer (rework A5). It sits INSIDE
        //     the throttle so a 429 still says 429, and OUTSIDE the gate
        //     so it can catch what the gate aborts with;
        //  3. the gate itself, on `console:key:write` — its OWN ability,
        //     NOT the `credential:rotate` family (rework B2). A re-key
        //     is a rotation in shape, but folding it into that family
        //     would have handed Console-admin takeover to every
        //     rotate-scoped credential already in the field, silently,
        //     on upgrade. `credential:admin` still satisfies it, because
        //     the break-glass is a marking someone chose.
        $router->post('/bfc/console/re-key', [ManageConsoleKeys::class, 'reKey'])
            ->middleware([
                'throttle:bfc-operator-write',
                UniformConsoleKeyRefusal::class,
                'bfc.credential.admin:'.OperatorAbility::ConsoleKeyWrite->value,
            ]);

        // The Console's ops-vitals read (Console PRD D9/D15/D16): a
        // `metadata`-classified surface at a fixed `/bfc/console/*`
        // path, an ordinary member of the routes family.
        //
        // Its gate is TWO layers, and neither is the operator gate every
        // verb route above uses.
        //
        //  1. `bfc.ability:metadata:read` — exact match. D16 forbids the
        //     ownership/admin credential on any dashboard read path, and
        //     `bfc.credential.admin` grants `credential:admin` whatever
        //     ability a route names, so mounting this behind it would
        //     have left the prohibition unenforced. This gate implies
        //     nothing and authenticates through the `bfc` guard, which
        //     never resolves a legacy `api_tokens` secret.
        //  2. EnsureDashboardCredential — operator subject, and an
        //     ability set EXACTLY equal to `{metadata:read}`. Membership
        //     is not what D16 asks for: a credential holding both
        //     `metadata:read` and `credential:admin` passes layer 1 and
        //     still mutates every operator surface, which is precisely
        //     the "unable to touch content-classified or mutating
        //     surfaces" clause failing.
        //
        // Rate-limited like every other credentialed surface, per
        // credential AND per IP, and the throttle sits OUTSIDE both
        // gates so refused attempts are bounded too.
        $router->get('/bfc/console/vitals', ConsoleVitals::class)
            ->middleware([
                'throttle:bfc-vitals',
                'bfc.ability:'.OperatorAbility::MetadataRead->value,
                EnsureDashboardCredential::class,
            ]);

        // The offboard verb (PRD 1.15, SEC-V3-04): full account
        // containment behind its OWN verb-family ability — the widest
        // verb, so a stolen mint- or revoke-scoped credential cannot
        // reach it.
        $router->post('/bfc/subjects/offboard', [ManageSubjects::class, 'offboard'])
            ->middleware(['throttle:bfc-operator-write', 'bfc.credential.admin:'.OperatorAbility::SubjectOffboard->value]);

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
     * The browser-session stack the personal surface rides (PRD 1.17,
     * rework Fix 1) — the CSRF protection on its mutating verbs included.
     *
     * PREFERRED: the host's own `web` group. It is the right answer in a
     * standard Laravel app for two reasons — it is the stack that app's
     * OWN settings screens run on (its cookie encryption, its session
     * driver, and whatever it added: locale, tenancy, impersonation), and
     * an app that customized CSRF handling gets its customization here
     * rather than a second, divergent copy.
     *
     * FALLBACK, when no such group is registered (a package test harness,
     * an API-only skeleton that never defined one): the concrete stack,
     * so these routes are never mounted WITHOUT session start and CSRF
     * validation. `PreventRequestForgery` exempts read verbs itself, so
     * the listing is not CSRF-checked while POST and DELETE are — and the
     * listing is where a front end picks up the XSRF-TOKEN cookie it will
     * send back.
     *
     * @return list<string>
     */
    private function personalSessionMiddleware(Router $router): array
    {
        if ($router->hasMiddlewareGroup('web')) {
            return ['web'];
        }

        return [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
            PreventRequestForgery::class,
        ];
    }

    /**
     * The artisan command family (PRD 1.14).
     */
    private function registerCommands(): void
    {
        $this->commands([
            ConsoleReKeyCommand::class,
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
            SubjectOffboardCommand::class,
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

        // The personal surface's limiter (PRD 1.17). Keyed on the
        // SESSION principal, not a bearer digest: this surface has no
        // bearer. The user id is read defensively — the limiter runs
        // before the session gate, and a headless app (no guard at all)
        // must get a bounded 401, never a 500 out of the AuthManager.
        RateLimiter::for('bfc-personal', function (Request $request): array {
            return [
                Limit::perMinute(30)->by('bfc-personal-user|'.($this->limiterPrincipal($request) ?? 'anonymous')),
                Limit::perMinute(60)->by('bfc-personal-ip|'.($request->ip() ?? 'unknown')),
            ];
        });

        // GATE-3.7 (rework Fix 5): write and expensive operator verbs
        // carry THREE independent bounds —
        //   1. per CREDENTIAL (sha256 of the presented bearer — the
        //      limiter runs before the gate resolves a row id, and the
        //      digest identifies the credential without persisting its
        //      plaintext), so a stolen credential is bounded ACROSS IPs;
        //   2. per IP, so rotating invalid bearer strings from one
        //      address buys no fresh budget per string; and
        //   3. the global ceiling.
        // A single compound credential|IP bucket would defeat both: a new
        // IP would refresh a stolen credential's budget, and a new bearer
        // string would refresh an attacker IP's.
        // The Console dashboard read (D16). Two independent bounds, the
        // same shape and for the same reasons as the operator-write
        // limiter below: a stolen dashboard credential is bounded across
        // every IP it is replayed from, and one address buys no fresh
        // budget by rotating bearer strings. No global ceiling —
        // vitals is a read, and one bucket shared by every deployment's
        // dashboard poll would let one busy app throttle the fleet.
        //
        // The per-IP bound is five times the per-credential one, and
        // deliberately so: readers SHARE an IP bucket, and the vendor's
        // whole control plane polls from one egress address, so a bound
        // set at 2x would let two saturated readers 429 a third
        // legitimate one. Five readers' worth of headroom costs nothing
        // against credential guessing — the secrets are 256-bit, so the
        // per-IP bucket was never the thing making them unguessable; it
        // bounds noise, not search.
        RateLimiter::for('bfc-vitals', function (Request $request): array {
            $bearer = $request->bearerToken();
            $credentialKey = $bearer === null || $bearer === '' ? 'anonymous' : hash('sha256', $bearer);

            return [
                Limit::perMinute(60)->by('bfc-vitals-cred|'.$credentialKey),
                Limit::perMinute(300)->by('bfc-vitals-ip|'.($request->ip() ?? 'unknown')),
            ];
        });

        RateLimiter::for('bfc-operator-write', function (Request $request): array {
            $bearer = $request->bearerToken();
            $credentialKey = $bearer === null || $bearer === '' ? 'anonymous' : hash('sha256', $bearer);

            return [
                Limit::perMinute(60)->by('bfc-op-cred|'.$credentialKey),
                Limit::perMinute(60)->by('bfc-op-ip|'.($request->ip() ?? 'unknown')),
                Limit::perMinute(600)->by('bfc-operator-write-global'),
            ];
        });
    }

    /**
     * The session principal a personal-surface limiter buckets on, or null
     * when there is none to resolve. Structural absence (no guard
     * configured at all, the headless case above) and a guard that throws
     * both mean "no principal": the request still gets its IP bucket and
     * then meets the session gate, which is what decides the answer.
     */
    private function limiterPrincipal(Request $request): ?string
    {
        try {
            $user = $request->user();
        } catch (Throwable) {
            return null;
        }

        if ($user === null) {
            return null;
        }

        $id = $user->getAuthIdentifier();

        return is_scalar($id) && (string) $id !== '' ? (string) $id : null;
    }
}
