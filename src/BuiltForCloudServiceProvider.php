<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Auth\HumanAuthConfiguration;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand;
use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialActivateCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\FreshCommand;
use ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand;
use ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand;
use ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand;
use ArtisanBuild\BuiltForCloud\Commands\PruneCredentialAuthorizationsCommand;
use ArtisanBuild\BuiltForCloud\Commands\SigningRootProvisionCommand;
use ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand;
use ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\Listeners\QueueOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Listeners\RefuseSystemAuthorityAuthentication;
use ArtisanBuild\BuiltForCloud\Listeners\SystemAuthorityQueueScope;
use ArtisanBuild\BuiltForCloud\View\Layout;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Bus\Dispatcher as BusDispatcher;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcherContract;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use ReflectionProperty;
use RuntimeException;
use Throwable;

final class BuiltForCloudServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/built-for-cloud.php', 'built-for-cloud');
        $this->app->booting(
            static fn (Application $app) => HumanAuthConfiguration::apply($app->make(Repository::class)),
        );

        $this->app->singleton(UsageReporter::class, NullUsageReporter::class);
        $this->app->singleton(SystemAuthorityContext::class);
        $this->app->singleton(SystemAuthorityQueueScope::class);
        $this->app->singleton(LandingManifest::class, static fn (): ?LandingManifest => LandingManifest::fromOptionalConfiguration());

        // P5b's forward-only carry: exchange has one durable destination.
        $this->app->bind(DurableCredentialMinter::class, UnifiedStoreCredentialMinter::class);
        $this->app->bind(ResolvesAsymmetricEnrollmentScope::class, NullAsymmetricEnrollmentScopeResolver::class);

        // The single resolved acting principal, one instance per
        // application, memoizing per REQUEST inside itself, so the
        // acting principal and its audit consumers cannot be computed
        // twice and disagree.
        $this->app->singleton(ActingPrincipalResolver::class);

        $this->app->bind(CredentialDeclaration::class, function (Application $app): CredentialDeclaration {
            /** @var class-string<CredentialDeclaration> $declaration */
            $declaration = config('built-for-cloud.credentials.declaration') ?? DefaultCredentialDeclaration::class;

            /** @var CredentialDeclaration */
            return $app->make($declaration);
        });
    }

    public function boot(): void
    {
        HumanAuthConfiguration::apply($this->app->make(Repository::class));

        Event::listen(Authenticated::class, [RefuseSystemAuthorityAuthentication::class, 'handle']);
        Event::listen(Login::class, [RefuseSystemAuthorityAuthentication::class, 'handle']);
        $this->frameQueueEntriesByInvocation();
        Event::listen(JobProcessing::class, [SystemAuthorityQueueScope::class, 'processing']);
        Event::listen(JobAttempted::class, [SystemAuthorityQueueScope::class, 'finished']);

        if ($this->app->resolved('auth')) {
            HumanAuthConfiguration::assertEffectiveProvider($this->app->make('auth'));
        }

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

        // The package view namespace. NOT a selectable surface, and for
        // the same reason the middleware aliases are not: it mounts
        // nothing. A namespace is a name an application has to reach
        // for — an app that never writes `bfc::` renders nothing of
        // ours — so there is no behaviour here for a flag to switch
        // off.
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'bfc');
        $this->registerLayout();

        if ($this->surfaceEnabled('listeners')) {
            Event::listen(OwnershipReleasePending::class, QueueOwnershipWebhook::class);
            Event::listen(OwnershipTransferred::class, QueueOwnershipWebhook::class);
        }

        $this->registerRateLimiters();
        $authoritySchedule = $this->app->make(SystemAuthoritySchedule::class);
        $this->callAfterResolving(
            'Illuminate\\Console\\Scheduling\\Schedule',
            static fn (mixed $schedule) => $authoritySchedule->registerCredentialAuthorizationPrune($schedule),
        );

        Auth::resolved(function (AuthManager $auth): void {
            $auth->extend('bfc', function (Application $app, string $name, array $config): CredentialGuard {
                /** @var array<string, mixed> $config */
                return new CredentialGuard($app, $name, $config, $app->make(CredentialResolver::class));
            });
        });

        if ($this->app->bound('router')) {
            /** @var Router $router */
            $router = $this->app['router'];

            $router->aliasMiddleware('bfc.auth', EnsureUserIsAuthenticated::class);
            $router->aliasMiddleware('bfc.contract-major', EnsureContractMajor::class);
            $router->aliasMiddleware('bfc.admin', EnsureUserIsAdmin::class);
            $router->aliasMiddleware('bfc.credential.admin', EnsureCredentialAdmin::class);
            $router->aliasMiddleware('bfc.ability', EnsureCredentialAbility::class);
            // The verify half of the hmac pair (PRD 1.21, SEC-V3-07):
            // consuming apps put it in front of signed-message routes.
            $router->aliasMiddleware('bfc.hmac', VerifyHmacSignature::class);
            $router->aliasMiddleware('bfc.mcp', AuthenticateMcp::class);
            $router->aliasMiddleware('bfc.standalone', EnsureStandaloneAuthority::class);
            $this->prioritizeContractMajorAdmission($router);

            // These convenience aliases remain public. Package operator routes
            // verify their resolved gate on match, and each final operator
            // controller derives its required gate from the action it is about
            // to execute and requires that gate's receipt before invocation.

            $this->loadRoutes($router);
        }

        if ($this->app->runningInConsole()) {
            if ($this->surfaceEnabled('commands')) {
                $this->registerCommands();
            }

            $this->publishes([
                __DIR__.'/../config/built-for-cloud.php' => $this->app->configPath('built-for-cloud.php'),
            ], 'built-for-cloud-config');

            // The package view namespace, publishable the ordinary
            // Laravel way. To replace the page shell, prefer naming a
            // layout class in BUILT_FOR_CLOUD_LAYOUT: a published copy
            // shadows the package view by name and stops receiving
            // upstream changes, while a configured class lives in a file
            // the package never ships.
            $this->publishes([
                __DIR__.'/../resources/views' => $this->app->resourcePath('views/vendor/bfc'),
            ], 'built-for-cloud-views');
        }
    }

    /** Keep opt-in contract admission ahead of every package authentication gate. */
    private function prioritizeContractMajorAdmission(Router $router): void
    {
        $config = $this->app->make(Repository::class);
        $authentication = [
            EnsureManagedAuthority::class,
            EnsureStandaloneAuthority::class,
            AuthenticateMcp::class,
            VerifyHmacSignature::class,
            EnsureDashboardCredential::class,
            EnsureCredentialAdmin::class,
            EnsureCredentialAbility::class,
            EnsureUserIsAuthenticated::class,
            EnsureUserIsAdmin::class,
        ];

        $router->matched(static function (RouteMatched $event) use ($authentication, $config, $router): void {
            $resolved = $router->resolveMiddleware(
                $event->route->gatherMiddleware(),
                $event->route->excludedMiddleware(),
            );
            $admission = RouteMiddleware::indexOfClass($resolved, EnsureContractMajor::class);

            if ($admission === null) {
                return;
            }

            $firstAuthentication = null;

            foreach ($resolved as $index => $middleware) {
                if (! is_string($middleware)) {
                    continue;
                }

                [$name, $parameters] = array_pad(explode(':', $middleware, 2), 2, null);
                $usesCredentialGuard = false;

                if (is_a($name, AuthenticatesRequests::class, true)) {
                    $guards = $parameters === null
                        ? [$config->get('auth.defaults.guard')]
                        : explode(',', $parameters);

                    foreach ($guards as $guard) {
                        $guardConfig = is_string($guard) ? $config->get('auth.guards.'.$guard) : null;

                        if (is_array($guardConfig) && ($guardConfig['driver'] ?? null) === 'bfc') {
                            $usesCredentialGuard = true;
                            break;
                        }
                    }
                }

                if ($usesCredentialGuard || in_array($name, $authentication, true)) {
                    $firstAuthentication = $index;
                    break;
                }
            }

            if ($firstAuthentication === null || $admission < $firstAuthentication) {
                return;
            }

            $admissionMiddleware = $resolved[$admission];
            array_splice($resolved, $admission, 1);
            array_splice($resolved, $firstAuthentication, 0, [$admissionMiddleware]);
            $event->route->computedMiddleware = $resolved;
        });
    }

    /**
     * Frames every package queue entry at its INVOCATION by appending a bus pipe.
     *
     * Appended rather than set: `Dispatcher::pipeThrough()` REPLACES the pipe array,
     * so writing it blind would drop any pipe a host app or another package
     * registered first. The existing pipes are read and preserved.
     *
     * KNOWN CEILING, disclosed rather than papered over: a host that calls
     * `Bus::pipeThrough()` AFTER this provider boots replaces the array again and
     * removes this frame. That is the same exposure any package has with this API.
     * The queue-event listeners are kept alongside as a second, independent
     * mechanism so the two cover each other.
     */
    private function frameQueueEntriesByInvocation(): void
    {
        $dispatcher = $this->app->make(BusDispatcherContract::class);

        if (! $dispatcher instanceof BusDispatcher) {
            return;
        }

        $pipes = (new ReflectionProperty(BusDispatcher::class, 'pipes'))->getValue($dispatcher);
        $pipes = is_array($pipes) ? $pipes : [];

        if (in_array(SystemAuthorityBusFrame::class, $pipes, true)) {
            return;
        }

        $pipes[] = SystemAuthorityBusFrame::class;
        $dispatcher->pipeThrough($pipes);
    }

    private function surfaceEnabled(string $surface): bool
    {
        return (bool) config('built-for-cloud.surfaces.'.$surface, true);
    }

    /**
     * Load routes/web.php and routes/api.php in every app, then hold each
     * route family the files mark to the ownership rules its controllers
     * rely on: reserved names and shapes for the landing, UI and standalone
     * pages, package middleware for every browser family, and the declared
     * gate for every operator route, checked at boot and again on each match.
     */
    private function loadRoutes(Router $router): void
    {
        $existing = $router->getRoutes()->getRoutes();
        $router->group([], __DIR__.'/../routes/web.php');
        $router->group([], __DIR__.'/../routes/api.php');
        $routes = array_values(array_filter(
            $router->getRoutes()->getRoutes(),
            static fn (Route $route): bool => ! in_array($route, $existing, true),
        ));
        $family = static fn (string ...$families): array => array_values(array_filter(
            $routes,
            static fn (Route $route): bool => in_array($route->getAction('bfc_family'), $families, true),
        ));

        $operatorRoutes = array_map(
            $this->protectOperatorRoute(...),
            array_values(array_filter($routes, static fn (Route $route): bool => $route->getAction('bfc_operator') === true)),
        );
        $bearerRoutes = array_values(array_filter($routes, static fn (Route $route): bool => $route->getAction('bfc_bearer') === true));
        $packageMiddlewareRoutes = StandaloneRouteOwnership::packageMiddlewareInventory(
            $family('ui', 'standalone', 'personal-credentials', 'installation-credentials', 'authorization'),
        );
        $ownedNamedRoutes = $family('landing', 'ui', 'standalone');

        $this->app->booted(function () use ($ownedNamedRoutes, $packageMiddlewareRoutes, $router): void {
            StandaloneRouteOwnership::assertOwned($router, $ownedNamedRoutes);
            StandaloneRouteOwnership::assertPackageMiddlewareOwned($router, $packageMiddlewareRoutes);
        });
        Event::listen(RouteMatched::class, static function (RouteMatched $event) use ($bearerRoutes, $ownedNamedRoutes, $packageMiddlewareRoutes, $router): void {
            StandaloneRouteOwnership::assertMatched($router, $event->route, $ownedNamedRoutes);
            StandaloneRouteOwnership::assertPackageMiddlewareMatched($router, $event->route, $packageMiddlewareRoutes);

            if (in_array($event->route, $bearerRoutes, true)) {
                // Include normal host middleware attached after an earlier
                // route gather. Uncached collections only: a compiled
                // collection reconstructs the matched route, so this object-
                // identity gate never matches there and the flush is inert —
                // a post-cache late attachment rides the framework's own
                // gather/mutate behavior instead. The security properties
                // (starter exclusion, zero bearer-request session writes,
                // clean 302 handoff) do not depend on this flush.
                $event->route->flushController();
            }
        });

        $this->app->booted(function () use ($operatorRoutes, $router): void {
            StandaloneRouteOwnership::assertOperatorOwned($router, $operatorRoutes);
        });

        // Wildcard listeners run after every ordinary RouteMatched listener,
        // including host listeners registered later than this provider.
        Event::listen(RouteMatched::class.'*', static function (string $event, array $payload) use ($operatorRoutes, $router): void {
            $matched = $payload[0] ?? null;

            if ($event === RouteMatched::class && $matched instanceof RouteMatched) {
                StandaloneRouteOwnership::assertOperatorMatched($router, $matched->route, $operatorRoutes);
            }
        });
    }

    /**
     * Append the gate the operator route inventory names for this route's
     * action, refusing a route whose action declares none.
     *
     * @return array{route: Route, gate: string}
     */
    private function protectOperatorRoute(Route $route): array
    {
        $gate = StandaloneRouteOwnership::operatorGateForAction($route->getActionName());

        if ($gate === null) {
            throw new RuntimeException("The route [{$route->uri()}] does not declare an operator-gated action.");
        }

        $route->middleware($gate);

        return ['route' => $route, 'gate' => $gate];
    }

    /**
     * The artisan command family (PRD 1.14).
     */
    private function registerCommands(): void
    {
        $this->commands([
            ConsoleReKeyCommand::class,
            ConsoleRetireKeyCommand::class,
            CreateAdminCommand::class,
            CredentialActivateCommand::class,
            CredentialListCommand::class,
            CredentialMintCommand::class,
            CredentialRevokeCommand::class,
            CredentialRotateCommand::class,
            FreshCommand::class,
            HmacRewrapCommand::class,
            InstallOperatorCredentialCommand::class,
            OutboxDrainCommand::class,
            OwnershipMintClaimCommand::class,
            OwnershipRemintOwnerTokenCommand::class,
            PruneCredentialAuthorizationsCommand::class,
            SigningRootProvisionCommand::class,
            SubjectOffboardCommand::class,
            WarnExpiringCredentialsCommand::class,
        ]);
    }

    /** Register `<x-bfc-layout>`, and point Livewire's full-page layout at the configured class unless the app opts out. */
    private function registerLayout(): void
    {
        Blade::component(Layout::class, 'layout', 'bfc');

        if (Config::boolean('built-for-cloud.livewire_layout', true)) {
            Config::set('livewire.component_layout', Config::string('built-for-cloud.layout', Layout::class));
        }
    }

    /**
     * BfC's management routes are public/pre-auth, and runtime configuration
     * can still remove every guard after the package installs its web guard.
     * Laravel's inline `throttle:N,1` builds its signature via
     * `$request->user()`, so on such an app the AuthManager throws and every
     * throttled route 500s. Keying these limiters on the IP is both correct for
     * pre-auth traffic and free of any guard resolution.
     */
    private function registerRateLimiters(): void
    {
        $slowDown = static function (Request $request, array $headers) {
            $retryAfter = max(1, min(30, (int) ($headers['Retry-After'] ?? 1)));

            return response()->json(
                ['error' => 'slow_down', 'interval' => $retryAfter],
                429,
                [...$headers, 'Cache-Control' => 'no-store', 'Pragma' => 'no-cache', 'Retry-After' => (string) $retryAfter],
            );
        };

        RateLimiter::for('bfc-authorization-start', fn (Request $request): Limit => Limit::perMinute(15)
            ->by('bfc-authorization-start|'.($this->limiterPrincipal($request) ?? 'anonymous').'|'.$this->limiterSourceIp($request))
            ->response($slowDown));

        RateLimiter::for('bfc-authorization-decision', fn (Request $request): Limit => Limit::perMinute(10)
            ->by('bfc-authorization-decision|'.($this->limiterPrincipal($request) ?? 'anonymous').'|'.$this->limiterSourceIp($request))
            ->response($slowDown));

        RateLimiter::for('bfc-authorization-token', fn (Request $request): array => [
            Limit::perMinute(120)->by(
                ($request->is('bfc/device/token') ? 'bfc-device-token|' : 'bfc-loopback-token|').$this->limiterSourceIp($request),
            )->response($slowDown),
            Limit::perMinute(6000)->by('bfc-authorization-token-global')->response($slowDown),
        ]);

        RateLimiter::for('bfc-public', fn (Request $request): Limit => Limit::perMinute(60)->by($request->ip() ?? 'unknown'));

        RateLimiter::for('bfc-claim', fn (Request $request): Limit => Limit::perMinute(10)->by($request->ip() ?? 'unknown'));

        RateLimiter::for('bfc-login', fn (Request $request): array => [
            Limit::perMinute(5)->by('bfc-login-address|'.StandaloneAccess::normalizeEmail((string) $request->input('email', ''))),
            Limit::perMinute(5)->by('bfc-login-ip|'.($request->ip() ?? 'unknown')),
        ]);

        RateLimiter::for('bfc-password-reset', fn (Request $request): array => [
            Limit::perMinute(5)->by('bfc-password-reset-address|'.StandaloneAccess::normalizeEmail((string) $request->input('email', ''))),
            Limit::perMinute(5)->by('bfc-password-reset-ip|'.($request->ip() ?? 'unknown')),
        ]);

        RateLimiter::for('bfc-invitation-issue', fn (Request $request): array => [
            Limit::perMinute(5)->by('bfc-invitation-issue-actor|'.($this->limiterPrincipal($request) ?? 'anonymous')),
            Limit::perMinute(5)->by('bfc-invitation-issue-address|'.StandaloneAccess::normalizeEmail((string) $request->input('email', ''))),
            Limit::perMinute(5)->by('bfc-invitation-issue-ip|'.($request->ip() ?? 'unknown')),
        ]);

        RateLimiter::for('bfc-session-confirm', fn (Request $request): array => [
            Limit::perMinute(4)->by('bfc-session-confirm-user|'.($this->limiterPrincipal($request) ?? 'anonymous')),
            Limit::perMinute(2)->by('bfc-session-confirm-session|'.($request->hasSession() ? $request->session()->getId() : 'none')),
            Limit::perMinute(6)->by('bfc-session-confirm-ip|'.($request->ip() ?? 'unknown')),
        ]);

        RateLimiter::for('bfc-invitation-accept', fn (Request $request): Limit => Limit::perMinute(10)->by(
            'bfc-invitation-accept|'.($request->ip() ?? 'unknown'),
        ));

        RateLimiter::for('bfc-bearer-handoff', fn (Request $request): Limit => Limit::perMinute(10)->by(
            'bfc-bearer-handoff|'.($request->ip() ?? 'unknown'),
        ));

        // The personal surface's limiter (PRD 1.17). Keyed on the
        // SESSION principal, not a bearer digest: this surface has no
        // bearer. The user id is read defensively — the limiter runs
        // before the session gate, and a runtime with no configured guard
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

    private function limiterSourceIp(Request $request): string
    {
        $ip = $request->ip() ?? 'unknown';
        $packed = @inet_pton($ip);

        if ($packed === false || strlen($packed) !== 16) {
            return $ip;
        }

        return (string) inet_ntop(substr($packed, 0, 8).str_repeat("\0", 8)).'/64';
    }
}
