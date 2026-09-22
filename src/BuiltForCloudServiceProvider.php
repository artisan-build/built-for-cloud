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
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use ArtisanBuild\BuiltForCloud\Http\Controllers\AsymmetricEnrollments;
use ArtisanBuild\BuiltForCloud\Http\Controllers\BoundHmacCutovers;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\DeviceAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\InstallationCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\LoopbackAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedEnrolments;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneMemberships;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandalonePasswordRecovery;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneSessions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiHome;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiInstallationCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiLogout;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiPersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\ExpireStandaloneHandoffOnRefusal;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\Listeners\QueueOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Listeners\RefuseSystemAuthorityAuthentication;
use ArtisanBuild\BuiltForCloud\Listeners\SystemAuthorityQueueScope;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Bus\Dispatcher as BusDispatcher;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcherContract;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Request;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\Middleware\ShareErrorsFromSession;
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

            // The package view namespace, publishable the ordinary
            // Laravel way so an app can restyle it without forking the
            // package. Publishing does NOT create a second layout:
            // Laravel's namespaced view finder prefers the published
            // copy over the package's for the SAME view name, so
            // `bfc::layout` still names one template — the app's, once
            // it has taken ownership of it.
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
     * The HTTP surface family (PRD 1.14): mounted whole, or not at all.
     */
    private function mountRoutes(Router $router): void
    {
        /** @var list<array{route: Route, gate: string}> $operatorRoutes */
        $operatorRoutes = [];
        $landingRoute = $this->app->make(LandingPageRegistrar::class)->mount($router);
        $landingRoutes = $landingRoute instanceof Route ? [$landingRoute] : [];

        $router->get('/bfc/meta', MetaController::class)
            ->middleware('throttle:bfc-public');

        $router->post('/bfc/ownership/claim', [ManageOwnership::class, 'claim'])
            ->middleware('throttle:bfc-claim');

        // The P1 managed-enrolment verbs: owner-credential-authenticated
        // (the CURRENT ownership-linked credential — not any admin
        // bearer), throttled before authentication like every operator
        // write, no-store, secret never returned. See
        // docs/http-contract.md "Authority-driven managed enrolment".
        $this->protectOperatorRoute(
            $router->post('/bfc/managed/enrolment', [ManagedEnrolments::class, 'enrol'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/managed/enrolment/client-secret', [ManagedEnrolments::class, 'rotateClientSecret'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/managed/enrolment/disconnect', [ManagedEnrolments::class, 'disconnect'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/ownership/release', [ManageOwnership::class, 'release']),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/ownership/cancel-transfer', [ManageOwnership::class, 'cancelTransfer']),
            $operatorRoutes,
        );

        // The hitch claim-contract route (PRD 1.12 / OSS-8): the wire
        // face of hitch/docs/claim-contract.md over the same claim
        // primitive as the onboarding exchange. Unconditional at a
        // FIXED path like every /bfc/* surface — never behind a
        // configurable prefix, never behind its own env flag.
        $router->post('/bfc/claim', [ManageOnboarding::class, 'claim'])
            ->middleware('throttle:bfc-claim');

        $this->protectOperatorRoute(
            $router->post('/bfc/onboarding/issue', [ManageOnboarding::class, 'issue']),
            $operatorRoutes,
        );

        $router->post('/bfc/onboarding/exchange', [ManageOnboarding::class, 'exchange'])
            ->middleware('throttle:bfc-claim');

        $router->post('/bfc/asymmetric-enrollments/{application}', AsymmetricEnrollments::class)
            ->middleware('throttle:bfc-claim');

        $router->post('/bfc/onboarding/verify', [ManageOnboarding::class, 'verify'])
            ->middleware('throttle:bfc-public');

        $this->protectOperatorRoute(
            $router->get('/bfc/client-observations', ClientObservations::class),
            $operatorRoutes,
        );

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
        $this->protectOperatorRoute(
            $router->get('/bfc/credentials', [ManageCredentials::class, 'index']),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/credentials', [ManageCredentials::class, 'store'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->delete('/bfc/credentials/{id}', [ManageCredentials::class, 'destroy'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/credentials/{id}/rotate', [ManageCredentials::class, 'rotate'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        // The hmac signing cutover (PRD 1.21, SEC-V3-01): a separate
        // operator-authorized verb — the claim exchange delivers and
        // never activates, so the flip needs its own route. Its
        // operator ability is the rotate FAMILY (activation completes
        // rotation's dance); the declaration matrix's own `activate`
        // verb stays the finer split.
        $this->protectOperatorRoute(
            $router->post('/bfc/credentials/{id}/activate', [ManageCredentials::class, 'activate'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/hmac-cutovers/activate', [BoundHmacCutovers::class, 'activate'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

        $this->protectOperatorRoute(
            $router->post('/bfc/hmac-cutovers/status', [BoundHmacCutovers::class, 'status'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

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
        // Personal and installation credential management are BROWSER
        // routes. They ride the full session stack — see
        // browserSessionMiddleware() — so cookie sessions actually start,
        // and so the MUTATING verbs are CSRF-protected. Without it a
        // session-riding forgery on a logged-in user's browser could mint,
        // rotate or revoke credentials.
        $personal = $this->browserSessionMiddleware($router);
        $authorizationUser = EnsureUserIsAuthenticated::class.':'.EnsureUserIsAuthenticated::DEFER_MANAGED_AUTHORITY;

        $authorizationRoutes = [];
        $authorizationRoutes[] = $router->post('/bfc/device-authorizations', [DeviceAuthorizations::class, 'store'])
            ->middleware([...$personal, $authorizationUser, 'throttle:bfc-authorization-start'])
            ->name('bfc.device.start');
        $authorizationRoutes[] = $router->get('/bfc/device', [DeviceAuthorizations::class, 'show'])
            ->middleware([...$personal, $authorizationUser])
            ->name('bfc.device.show');
        $authorizationRoutes[] = $router->post('/bfc/device', [DeviceAuthorizations::class, 'decide'])
            ->middleware([...$personal, $authorizationUser, 'throttle:bfc-authorization-decision'])
            ->name('bfc.device.decide');
        $authorizationRoutes[] = $router->post('/bfc/device/token', [DeviceAuthorizations::class, 'token'])
            ->middleware('throttle:bfc-authorization-token')
            ->name('bfc.device.token');
        $authorizationRoutes[] = $router->get('/bfc/loopback/authorize', [LoopbackAuthorizations::class, 'show'])
            ->middleware([...$personal, $authorizationUser, 'throttle:bfc-authorization-start'])
            ->name('bfc.loopback.authorize');
        $authorizationRoutes[] = $router->post('/bfc/loopback/authorize', [LoopbackAuthorizations::class, 'decide'])
            ->middleware([...$personal, $authorizationUser, 'throttle:bfc-authorization-decision'])
            ->name('bfc.loopback.decide');
        $authorizationRoutes[] = $router->post('/bfc/loopback/token', [LoopbackAuthorizations::class, 'token'])
            ->middleware('throttle:bfc-authorization-token')
            ->name('bfc.loopback.token');

        $uiRoutes = [];
        $uiRoutes[] = $router->get('/bfc/ui', UiHome::class)
            ->middleware([...$personal, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class])
            ->name('bfc.ui.home');
        $uiRoutes[] = $router->post('/bfc/ui/logout', UiLogout::class)
            ->middleware([...$personal, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class])
            ->name('bfc.ui.logout');
        $personalUiMiddleware = ['throttle:bfc-personal', ...$personal, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class];
        $uiRoutes[] = $router->get('/bfc/ui/credentials/personal', [UiPersonalCredentials::class, 'index'])
            ->middleware($personalUiMiddleware)
            ->name('bfc.ui.personal-credentials.index');
        $uiRoutes[] = $router->post('/bfc/ui/credentials/personal', [UiPersonalCredentials::class, 'store'])
            ->middleware($personalUiMiddleware)
            ->name('bfc.ui.personal-credentials.store');
        $uiRoutes[] = $router->post('/bfc/ui/credentials/personal/{id}/rotate', [UiPersonalCredentials::class, 'rotate'])
            ->middleware($personalUiMiddleware)
            ->name('bfc.ui.personal-credentials.rotate');
        $uiRoutes[] = $router->delete('/bfc/ui/credentials/personal/{id}', [UiPersonalCredentials::class, 'destroy'])
            ->middleware($personalUiMiddleware)
            ->name('bfc.ui.personal-credentials.destroy');
        $installationUiMiddleware = ['throttle:bfc-personal', ...$personal, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class];
        $uiRoutes[] = $router->get('/bfc/ui/credentials/installation', [UiInstallationCredentials::class, 'index'])
            ->middleware($installationUiMiddleware)
            ->name('bfc.ui.installation-credentials.index');
        $uiRoutes[] = $router->post('/bfc/ui/credentials/installation', [UiInstallationCredentials::class, 'store'])
            ->middleware($installationUiMiddleware)
            ->name('bfc.ui.installation-credentials.store');
        $uiRoutes[] = $router->post('/bfc/ui/credentials/installation/{id}/rotate', [UiInstallationCredentials::class, 'rotate'])
            ->middleware($installationUiMiddleware)
            ->name('bfc.ui.installation-credentials.rotate');
        $uiRoutes[] = $router->delete('/bfc/ui/credentials/installation/{id}', [UiInstallationCredentials::class, 'destroy'])
            ->middleware($installationUiMiddleware)
            ->name('bfc.ui.installation-credentials.destroy');

        $router->get('/bfc/managed/login', [ManagedAuthentication::class, 'create'])
            ->middleware([EnsureManagedAuthority::class, ...$personal])
            ->name('bfc.managed.login');
        $router->get('/bfc/managed/callback', [ManagedAuthentication::class, 'callback'])
            ->middleware([EnsureManagedAuthority::class, ...$personal])
            ->name('bfc.managed.callback');

        $router->middleware([...$personal, EnsureUserIsAuthenticated::class])->group(function (Router $router): void {
            $router->get('/bfc/transitions/{direction}/prepare', [ManageTransitions::class, 'index'])
                ->whereIn('direction', ManagedTransitionDirection::values())
                ->name('bfc.transitions.index');
            $router->post('/bfc/transitions/{direction}/prepare', [ManageTransitions::class, 'store'])
                ->whereIn('direction', ManagedTransitionDirection::values())
                ->name('bfc.transitions.store');
            $router->get('/bfc/transitions/proposals/{transition}', [ManageTransitions::class, 'edit'])
                ->name('bfc.transitions.edit');
            $router->put('/bfc/transitions/proposals/{transition}', [ManageTransitions::class, 'update'])
                ->name('bfc.transitions.update');
            $router->post('/bfc/transitions/proposals/{transition}/complete', [ManageTransitions::class, 'complete'])
                ->name('bfc.transitions.complete');
            $router->post('/bfc/transitions/proposals/{transition}/abandon', [ManageTransitions::class, 'abandon'])
                ->name('bfc.transitions.abandon');
        });

        $handoffMiddleware = [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            ExpireStandaloneHandoffOnRefusal::class,
        ];
        $handoffSessionMiddleware = [
            ...$handoffMiddleware,
            EnsureStandaloneAuthority::class,
            ...$personal,
        ];
        $standaloneRoutes = [];
        $standaloneRoutes[] = $router->get('/bfc/reset-password', [StandalonePasswordRecovery::class, 'edit'])
            ->middleware($handoffSessionMiddleware)
            ->name('bfc.password.reset.form');
        $standaloneRoutes[] = $router->post('/bfc/reset-password', [StandalonePasswordRecovery::class, 'update'])
            ->middleware([...$handoffSessionMiddleware, 'throttle:bfc-password-reset'])
            ->name('bfc.password.update');
        $standaloneRoutes[] = $router->get('/bfc/invitations/accept', [StandaloneInvitations::class, 'show'])
            ->middleware($handoffSessionMiddleware)
            ->name('bfc.invitations.accept.form');
        $standaloneRoutes[] = $router->post('/bfc/invitations/accept', [StandaloneInvitations::class, 'store'])
            ->middleware([...$handoffSessionMiddleware, 'throttle:bfc-invitation-accept'])
            ->name('bfc.invitations.accept.store');

        $bearerPageMiddleware = [
            ...$handoffMiddleware,
            'throttle:bfc-bearer-handoff',
            EnsureStandaloneAuthority::class,
        ];
        $bearerRoutes = [];
        $bearerRoutes[] = $standaloneRoutes[] = $router->get('/bfc/reset-password/{token}', [StandalonePasswordRecovery::class, 'handoff'])
            ->middleware($bearerPageMiddleware)
            ->withoutMiddleware([StartSession::class])
            ->name('bfc.password.reset');
        $bearerRoutes[] = $standaloneRoutes[] = $router->get('/bfc/invitations/{token}', [StandaloneInvitations::class, 'handoff'])
            ->middleware($bearerPageMiddleware)
            ->withoutMiddleware([StartSession::class])
            ->name('bfc.invitations.accept');

        $router->middleware([EnsureStandaloneAuthority::class, ...$personal])->group(function (Router $router) use (&$standaloneRoutes): void {
            $standaloneRoutes[] = $router->get('/bfc/login', [StandaloneAuthentication::class, 'create'])
                ->name('bfc.login');
            $standaloneRoutes[] = $router->post('/bfc/login', [StandaloneAuthentication::class, 'store'])
                ->middleware('throttle:bfc-login')
                ->name('bfc.login.store');
            $standaloneRoutes[] = $router->get('/bfc/forgot-password', [StandalonePasswordRecovery::class, 'create'])
                ->name('bfc.password.request');
            $standaloneRoutes[] = $router->post('/bfc/forgot-password', [StandalonePasswordRecovery::class, 'store'])
                ->middleware('throttle:bfc-password-reset')
                ->name('bfc.password.email');
        });

        $protectedStandaloneMiddleware = [
            EnsureUiAuthority::class,
            ...$personal,
            $authorizationUser,
            EnsureStandaloneAuthority::class,
        ];
        $router->middleware($protectedStandaloneMiddleware)->group(function (Router $router) use (&$standaloneRoutes): void {
            $standaloneRoutes[] = $router->get('/bfc/members', [StandaloneMemberships::class, 'index'])
                ->name('bfc.members.index');
            $standaloneRoutes[] = $router->post('/bfc/members/invitations', [StandaloneMemberships::class, 'invite'])
                ->middleware('throttle:bfc-invitation-issue')
                ->name('bfc.members.invitations.store');
            $standaloneRoutes[] = $router->put('/bfc/members/{user}/role', [StandaloneMemberships::class, 'role'])
                ->name('bfc.members.role.update');
            $standaloneRoutes[] = $router->delete('/bfc/members/{user}', [StandaloneMemberships::class, 'deactivate'])
                ->name('bfc.members.destroy');

            $standaloneRoutes[] = $router->get('/bfc/me/sessions', [StandaloneSessions::class, 'index'])
                ->name('bfc.sessions.index');
            $standaloneRoutes[] = $router->delete('/bfc/me/sessions/others', [StandaloneSessions::class, 'destroyOthers'])
                ->middleware('throttle:bfc-session-confirm')
                ->name('bfc.sessions.destroy-others');
            $standaloneRoutes[] = $router->delete('/bfc/me/sessions/{session}', [StandaloneSessions::class, 'destroy'])
                ->middleware('throttle:bfc-session-confirm')
                ->name('bfc.sessions.destroy');
            $standaloneRoutes[] = $router->post('/bfc/logout', [StandaloneAuthentication::class, 'destroy'])
                ->name('bfc.logout');
        });
        $personalCredentialRoutes = [];
        $personalCredentialRoutes[] = $router->get('/bfc/me/credentials', [PersonalCredentials::class, 'index'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);

        $personalCredentialRoutes[] = $router->post('/bfc/me/credentials', [PersonalCredentials::class, 'store'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);

        $personalCredentialRoutes[] = $router->delete('/bfc/me/credentials/{id}', [PersonalCredentials::class, 'destroy'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);

        $installationCredentialRoutes = [];
        $installationCredentialRoutes[] = $router->get('/bfc/installation/credentials', [InstallationCredentials::class, 'index'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);
        $installationCredentialRoutes[] = $router->post('/bfc/installation/credentials', [InstallationCredentials::class, 'store'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);
        $installationCredentialRoutes[] = $router->post('/bfc/installation/credentials/{id}/rotate', [InstallationCredentials::class, 'rotate'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);
        $installationCredentialRoutes[] = $router->delete('/bfc/installation/credentials/{id}', [InstallationCredentials::class, 'destroy'])
            ->middleware(['throttle:bfc-personal', ...$personal, EnsureUserIsAuthenticated::class]);

        $packageMiddlewareRoutes = StandaloneRouteOwnership::packageMiddlewareInventory([
            ...$uiRoutes,
            ...$standaloneRoutes,
            ...$personalCredentialRoutes,
            ...$installationCredentialRoutes,
            ...$authorizationRoutes,
        ]);

        $ownedNamedRoutes = [...$landingRoutes, ...$uiRoutes, ...$standaloneRoutes];

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
        $this->protectOperatorRoute(
            $router->post('/bfc/console/re-key', [ManageConsoleKeys::class, 'reKey'])
                ->middleware([
                    'throttle:bfc-operator-write',
                    UniformConsoleKeyRefusal::class,
                ]),
            $operatorRoutes,
        );

        // The retirement verb (Console PRD D12): the other half of
        // make-before-break, and until this release the half with no
        // operator path at all — the keyring primitive it drives took a
        // PHP caller and nothing else, so a rotation driven over the
        // wire could only ever be started, never finished.
        //
        // The `kid` rides the PATH because the verb acts on a row that
        // already exists — the shape `/bfc/credentials/{id}/rotate`
        // uses — where the re-key's flat body carries a key that does
        // not exist yet.
        //
        // The SAME stack as the re-key, layer for layer, and the same
        // ability. Retirement ends a signing authority where filing
        // begins one, which sounds like the more consequential half and
        // is not: a credential holding `console:key:write` can already
        // file and activate a key of its own and enter as a delegated
        // admin, which is more than denying entry. A separate ability
        // would have meant no credential already in the field could
        // finish a rotation without being reissued first.
        $this->protectOperatorRoute(
            $router->post('/bfc/console/keys/{key_id}/retire', [ManageConsoleKeys::class, 'retire'])
                ->middleware([
                    'throttle:bfc-operator-write',
                    UniformConsoleKeyRefusal::class,
                ]),
            $operatorRoutes,
        );

        // The Console's ops-vitals read (Console PRD D9/D15/D16): a
        // `metadata`-classified surface at a fixed `/bfc/console/*`
        // path, an ordinary member of the routes family.
        //
        // ONE gate, not the operator gate every verb route above uses
        // and not a composition either. {@see EnsureDashboardCredential}
        // is the whole of D16 — authentication, the app declaration's
        // authorization hook, an operator subject, and an ability set
        // EXACTLY equal to `{metadata:read}`.
        //
        // `bfc.credential.admin` could never have gated this: it grants
        // `credential:admin` whatever ability a route names, and D16
        // forbids the ownership/admin credential on any dashboard read
        // path. `bfc.ability:metadata:read` was in front of this gate
        // for one revision and has been removed: it enforces a strict
        // SUBSET of what the gate below enforces, so it never changed an
        // answer, while its own denial audit drained the delivery outbox
        // — putting the amplification lever this route was hardened
        // against back in front of the hardening. A redundant gate is a
        // second code path with its own side effects on the
        // attacker-reachable branch.
        //
        // Rate-limited like every other credentialed surface, per
        // credential AND per IP, and the throttle sits OUTSIDE the gate
        // so refused attempts are bounded too.
        $this->protectOperatorRoute(
            $router->get('/bfc/console/vitals', ConsoleVitals::class)
                ->middleware('throttle:bfc-vitals'),
            $operatorRoutes,
        );

        // The offboard verb (PRD 1.15, SEC-V3-04): full account
        // containment behind its OWN verb-family ability — the widest
        // verb, so a stolen mint- or revoke-scoped credential cannot
        // reach it.
        $this->protectOperatorRoute(
            $router->post('/bfc/subjects/offboard', [ManageSubjects::class, 'offboard'])
                ->middleware('throttle:bfc-operator-write'),
            $operatorRoutes,
        );

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
     * @param  list<array{route: Route, gate: string}>  $operatorRoutes
     */
    private function protectOperatorRoute(Route $route, array &$operatorRoutes): Route
    {
        $gate = StandaloneRouteOwnership::operatorGateForAction($route->getActionName());

        if ($gate === null) {
            throw new RuntimeException("The route [{$route->uri()}] does not declare an operator-gated action.");
        }

        $route->middleware($gate);
        $operatorRoutes[] = ['route' => $route, 'gate' => $gate];

        return $route;
    }

    /**
     * The browser-session stack the package's BROWSER routes ride — the
     * personal-credentials surface (PRD 1.17, rework Fix 1), the CSRF
     * protection on its mutating verbs included.
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
    private function browserSessionMiddleware(Router $router): array
    {
        if ($router->hasMiddlewareGroup('web')) {
            return ['web'];
        }

        return [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
            ShareErrorsFromSession::class,
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
            ConsoleRetireKeyCommand::class,
            CreateAdminCommand::class,
            CredentialActivateCommand::class,
            CredentialListCommand::class,
            CredentialMintCommand::class,
            CredentialRevokeCommand::class,
            CredentialRotateCommand::class,
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
