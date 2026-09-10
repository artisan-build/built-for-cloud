<?php

declare(strict_types=1);
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Http\Kernel as KernelContract;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

require __DIR__.'/../../vendor/autoload.php';

final class BfcExclusionProbeState
{
    public static int $customBuilds = 0;

    public static int $customRequests = 0;

    public static int $customTerminates = 0;

    public static int $hostRequests = 0;

    public static int $hostSessionRequests = 0;

    /** @var array<string, int> */
    public static array $preCacheCounts = [];
}

final class BfcExclusionProbeStartSession extends StartSession
{
    public function probeApi(): string
    {
        return 'custom-api';
    }

    public function handle($request, Closure $next)
    {
        BfcExclusionProbeState::$customRequests++;

        return parent::handle($request, $next);
    }

    public function terminate(Request $request, Response $response): void
    {
        BfcExclusionProbeState::$customTerminates++;
    }
}

final class BfcExclusionBaseConsumer
{
    public function __construct(public StartSession $starter) {}
}

final class BfcExclusionCustomConsumer
{
    public function __construct(public BfcExclusionProbeStartSession $starter) {}
}

final class BfcExclusionHostMiddleware
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        BfcExclusionProbeState::$hostRequests++;
        BfcExclusionProbeState::$hostSessionRequests += (int) $request->hasSession();
        $response = $next($request);
        $response->headers->set('X-Bfc-Exclusion-Host', 'ran');

        return $response;
    }
}

final class BfcExclusionHostProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(BfcExclusionProbeStartSession::class, function (Application $app): BfcExclusionProbeStartSession {
            BfcExclusionProbeState::$customBuilds++;

            return new BfcExclusionProbeStartSession(
                $app->make(SessionManager::class),
                static fn (): CacheFactory => $app->make(CacheFactory::class),
            );
        });
    }

    public function boot(Router $router): void
    {
        $scenario = self::scenario();

        if (str_starts_with($scenario, 'booted-')) {
            $this->app->booted(fn () => self::mutateRoutes($router, 'direct'));
        }

        if (str_starts_with($scenario, 'matched-')) {
            $this->app['events']->listen(RouteMatched::class, static function (RouteMatched $event): void {
                if (in_array($event->route->getName(), self::bearerRouteNames(), true)) {
                    self::mutateRoute($event->route, self::starterClass(), 'direct');
                }
            });
        }
    }

    public static function scenario(): string
    {
        return $_SERVER['BFC_EXCLUSION_SCENARIO'] ?? '';
    }

    /** @return class-string<StartSession> */
    public static function starterClass(): string
    {
        return str_ends_with(self::scenario(), '-custom')
            ? BfcExclusionProbeStartSession::class
            : StartSession::class;
    }

    /** @return list<string> */
    public static function bearerRouteNames(): array
    {
        return ['bfc.password.reset', 'bfc.invitations.accept'];
    }

    public static function mutateRoutes(Router $router, string $shape): void
    {
        $starter = self::starterClass();
        $group = self::groupName();

        if ($shape === 'group') {
            $router->middlewareGroup($group, [BfcExclusionHostMiddleware::class, $starter]);
        } elseif ($shape === 'alias') {
            $router->aliasMiddleware($group, $starter);
        } elseif ($shape === 'nested') {
            $inner = $group.'.inner';
            $router->middlewareGroup($inner, [$starter]);
            $router->middlewareGroup($group, [BfcExclusionHostMiddleware::class, $inner]);
        }

        foreach (self::bearerRouteNames() as $name) {
            $route = $router->getRoutes()->getByName($name);

            if (! $route instanceof Route) {
                throw new RuntimeException('The bearer handoff route was unavailable to the late host provider.');
            }

            self::mutateRoute($route, $starter, $shape);
        }
    }

    public static function groupName(): string
    {
        return 'bfc.exclusion.probe.'.str_replace('-', '.', self::scenario());
    }

    /** @param class-string<StartSession> $starter */
    private static function mutateRoute(Route $route, string $starter, string $shape): void
    {
        $route->middleware(match ($shape) {
            'group', 'nested' => self::groupName(),
            'alias' => [BfcExclusionHostMiddleware::class, self::groupName()],
            default => [BfcExclusionHostMiddleware::class, $starter],
        });
    }
}

final class BfcExclusionLateProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        BfcExclusionHostProvider::mutateRoutes($router, 'direct');
    }
}

$scenario = $argv[1] ?? '';
$scenarios = [
    'provider-base',
    'provider-custom',
    'booted-base',
    'booted-custom',
    'post-kernel-base',
    'post-kernel-custom',
    'matched-base',
    'matched-custom',
    'group-base',
    'group-custom',
    'alias-base',
    'alias-custom',
    'nested-base',
    'nested-custom',
    'post-cache-base',
    'post-cache-custom',
];

if (! in_array($scenario, $scenarios, true)) {
    fwrite(STDERR, "Unknown bearer exclusion probe.\n");
    exit(2);
}

$_SERVER['BFC_EXCLUSION_SCENARIO'] = $scenario;

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcExclusionHostProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'database');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('s', 32)));
    }

    /** @return array<string, mixed> */
    public function runProbe(): array
    {
        parent::setUp();
        /** @var Router $router */
        $router = $this->app['router'];

        if (str_starts_with(BfcExclusionHostProvider::scenario(), 'provider-')) {
            $this->app->register(BfcExclusionLateProvider::class);
        }

        $kernel = $this->app->make(KernelContract::class);
        $scenario = BfcExclusionHostProvider::scenario();

        if (str_starts_with($scenario, 'post-kernel-')) {
            BfcExclusionHostProvider::mutateRoutes($router, 'direct');
        }

        if (str_starts_with($scenario, 'group-')) {
            BfcExclusionHostProvider::mutateRoutes($router, 'group');
        }

        if (str_starts_with($scenario, 'alias-')) {
            BfcExclusionHostProvider::mutateRoutes($router, 'alias');
        }

        if (str_starts_with($scenario, 'nested-')) {
            BfcExclusionHostProvider::mutateRoutes($router, 'nested');
        }

        if (str_starts_with($scenario, 'post-cache-')) {
            foreach (BfcExclusionHostProvider::bearerRouteNames() as $name) {
                $route = $router->getRoutes()->getByName($name);

                if (! $route instanceof Route) {
                    throw new RuntimeException('The bearer handoff route was unavailable before the post-cache mutation.');
                }

                BfcExclusionProbeState::$preCacheCounts[$name] = count($route->gatherMiddleware());
            }

            BfcExclusionHostProvider::mutateRoutes($router, 'direct');
        }

        $this->artisan('migrate:fresh', ['--force' => true])->run();
        $user = User::query()->create([
            'name' => 'Exclusion Probe User',
            'email' => 'exclusion-probe@example.test',
            'password' => Hash::make('exclusion probe password'),
        ]);
        $user->forceFill([
            'role' => UserRole::Member->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $user->email,
        ])->save();
        $resetToken = 'reset-exclusion-probe';
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => hash('sha256', $resetToken),
            'created_at' => now(),
        ]);
        $invitationToken = 'invitation-exclusion-probe';
        Invitation::query()->create([
            'id' => (string) Str::uuid(),
            'email' => 'exclusion-invitee@example.test',
            'token' => Invitation::hashToken($invitationToken),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);
        $sessionWrites = 0;

        DB::listen(static function (QueryExecuted $query) use (&$sessionWrites): void {
            if (preg_match('/^(insert into|update) ["`]?sessions["`]?/i', ltrim($query->sql)) === 1) {
                $sessionWrites++;
            }
        });

        $responses = [];

        foreach ([
            '/bfc/reset-password/'.$resetToken => '/bfc/reset-password',
            '/bfc/invitations/'.$invitationToken => '/bfc/invitations/accept',
        ] as $path => $cleanPath) {
            $request = Request::create($path, 'GET');
            $response = $kernel->handle($request);
            $handoffCookies = array_values(array_filter(
                $response->headers->getCookies(),
                static fn ($cookie): bool => $cookie->getName() === StandaloneHandoff::COOKIE,
            ));
            $responses[] = [
                'status' => $response->getStatusCode(),
                'location' => parse_url((string) $response->headers->get('Location'), PHP_URL_PATH),
                'host' => $response->headers->get('X-Bfc-Exclusion-Host'),
                'handoff_cookies' => count($handoffCookies),
                'session_cookie' => array_filter(
                    $response->headers->getCookies(),
                    static fn ($cookie): bool => $cookie->getName() === config('session.cookie'),
                ) !== [],
                'clean_path' => $cleanPath,
            ];
            $kernel->terminate($request, $response);
        }

        $effectiveMiddleware = [];
        $rawMiddleware = [];
        $excludedMiddleware = [];
        $attachments = [];
        $groups = $router->getMiddlewareGroups();
        $aliases = $router->getMiddleware();

        foreach (BfcExclusionHostProvider::bearerRouteNames() as $name) {
            $route = $router->getRoutes()->getByName($name);
            $effectiveMiddleware[$name] = $router->gatherRouteMiddleware($route);
            $rawMiddleware[$name] = $route->middleware();
            $excludedMiddleware[$name] = $route->excludedMiddleware();
            $attachments[$name] = match (true) {
                str_starts_with($scenario, 'group-') => in_array(BfcExclusionHostProvider::groupName(), $rawMiddleware[$name], true)
                    && in_array(BfcExclusionHostProvider::starterClass(), $groups[BfcExclusionHostProvider::groupName()] ?? [], true),
                str_starts_with($scenario, 'alias-') => in_array(BfcExclusionHostProvider::groupName(), $rawMiddleware[$name], true)
                    && ($aliases[BfcExclusionHostProvider::groupName()] ?? null) === BfcExclusionHostProvider::starterClass(),
                str_starts_with($scenario, 'nested-') => in_array(BfcExclusionHostProvider::groupName(), $rawMiddleware[$name], true)
                    && in_array(BfcExclusionHostProvider::groupName().'.inner', $groups[BfcExclusionHostProvider::groupName()] ?? [], true)
                    && in_array(BfcExclusionHostProvider::starterClass(), $groups[BfcExclusionHostProvider::groupName().'.inner'] ?? [], true),
                default => in_array(BfcExclusionHostProvider::starterClass(), $rawMiddleware[$name], true),
            };
        }

        $base = $this->app->make(StartSession::class);
        $custom = $this->app->make(BfcExclusionProbeStartSession::class);
        $baseConsumer = $this->app->make(BfcExclusionBaseConsumer::class);
        $customConsumer = $this->app->make(BfcExclusionCustomConsumer::class);

        return [
            'responses' => $responses,
            'session_writes' => $sessionWrites,
            'effective_middleware' => $effectiveMiddleware,
            'raw_middleware' => $rawMiddleware,
            'excluded_middleware' => $excludedMiddleware,
            'attachments' => $attachments,
            'starter' => BfcExclusionHostProvider::starterClass(),
            'custom_builds' => BfcExclusionProbeState::$customBuilds,
            'custom_requests' => BfcExclusionProbeState::$customRequests,
            'custom_terminates' => BfcExclusionProbeState::$customTerminates,
            'host_requests' => BfcExclusionProbeState::$hostRequests,
            'host_session_requests' => BfcExclusionProbeState::$hostSessionRequests,
            'pre_cache_counts' => BfcExclusionProbeState::$preCacheCounts,
            'base_identity' => $baseConsumer->starter === $base,
            'custom_identity' => $customConsumer->starter === $custom,
            'custom_api' => $custom->probeApi(),
        ];
    }

    public function test_probe(): void {}
};

try {
    $result = $case->runProbe();
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

$valid = $result['session_writes'] === 0
    && $result['custom_requests'] === 0
    && $result['custom_terminates'] === 0
    && $result['host_requests'] === 2
    && $result['host_session_requests'] === 0
    && $result['base_identity']
    && $result['custom_identity']
    && $result['custom_api'] === 'custom-api'
    && $result['custom_builds'] === 1
    && (! str_starts_with($scenario, 'post-cache-')
        || count($result['pre_cache_counts']) === 2
        && min($result['pre_cache_counts']) > 0);

foreach ($result['responses'] as $response) {
    $valid = $valid
        && $response['status'] === 302
        && $response['location'] === $response['clean_path']
        && $response['host'] === 'ran'
        && $response['handoff_cookies'] === 1
        && $response['session_cookie'] === false;
}

foreach (BfcExclusionHostProvider::bearerRouteNames() as $name) {
    $effective = $result['effective_middleware'][$name];
    $excluded = $result['excluded_middleware'][$name];
    $valid = $valid
        && in_array(StartSession::class, $excluded, true)
        && $result['attachments'][$name]
        && in_array(BfcExclusionHostMiddleware::class, $effective, true)
        && array_filter(
            $effective,
            static fn (mixed $middleware): bool => is_string($middleware)
                && is_a(explode(':', $middleware, 2)[0], StartSession::class, true),
        ) === [];
}

if (! $valid) {
    fwrite(STDERR, sprintf(
        "Bearer exclusion probe failed: writes=%d custom_requests=%d host_requests=%d host_session_requests=%d.\n",
        $result['session_writes'],
        $result['custom_requests'],
        $result['host_requests'],
        $result['host_session_requests'],
    ));
    exit(1);
}

fwrite(STDOUT, $scenario."-exclusion-ok\n");
