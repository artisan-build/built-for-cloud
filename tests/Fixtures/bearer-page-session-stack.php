<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Http\Middleware\PreventBearerUrlPersistence;
use ArtisanBuild\BuiltForCloud\Http\Middleware\RestoreBearerRequestClassification;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Http\Kernel as KernelContract;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

require __DIR__.'/../../vendor/autoload.php';

final class BfcProbeState
{
    public static int $providerBoots = 0;

    public static int $bootedMutations = 0;

    public static int $customBuilds = 0;

    public static int $customRequests = 0;

    public static int $customTerminates = 0;

    public static int $customNormalTerminates = 0;

    /** @var array<string, int> */
    public static array $hostRequests = [];

    public static int $cachedRouteRequests = 0;
}

final class BfcProbeStartSession extends StartSession
{
    public function probeApi(): string
    {
        return 'custom-api';
    }

    public function handle($request, Closure $next)
    {
        BfcProbeState::$customRequests++;
        $response = parent::handle($request, $next);
        $response->headers->set('X-Bfc-Custom-Session', $request->prefetch() ? 'prefetch' : 'normal');

        return $response;
    }

    public function terminate(Request $request, Response $response): void
    {
        BfcProbeState::$customTerminates++;
        BfcProbeState::$customNormalTerminates += (int) ! $request->prefetch();
    }
}

final class BfcProbeBaseConsumer
{
    public function __construct(public StartSession $starter) {}
}

final class BfcProbeCustomConsumer
{
    public function __construct(public BfcProbeStartSession $starter) {}
}

final class BfcProbeHostMiddleware
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next, string $position): Response
    {
        BfcProbeState::$hostRequests[$position] = (BfcProbeState::$hostRequests[$position] ?? 0) + 1;
        $inbound = $request->isMethod('GET') && ! $request->prefetch() ? 'original' : 'changed';
        $response = $next($request);
        $unwind = $request->isMethod('GET') && ! $request->prefetch() ? 'original' : 'changed';
        $response->headers->set("X-Bfc-Host-{$position}", $inbound.'-'.$unwind);

        return $response;
    }
}

final class BfcProbeCachedRouteMiddleware
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        BfcProbeState::$cachedRouteRequests++;
        $response = $next($request);
        $response->headers->set('X-Bfc-Cached-Route', 'ran');

        return $response;
    }
}

final class BfcProbeHostProvider extends ServiceProvider
{
    public function register(): void
    {
        if (in_array(self::targetShape(), ['custom', 'duplicate'], true)) {
            $this->app->singleton(BfcProbeStartSession::class, function (Application $app): BfcProbeStartSession {
                BfcProbeState::$customBuilds++;

                return new BfcProbeStartSession(
                    $app->make(SessionManager::class),
                    static fn (): CacheFactory => $app->make(CacheFactory::class),
                );
            });
        }

        self::configureWebGroup($this->app['router'], 'base', includeLate: false);
    }

    public function boot(Router $router): void
    {
        BfcProbeState::$providerBoots++;
        $scenario = self::scenario();

        if (str_starts_with($scenario, 'booted-')) {
            self::configureWebGroup($router, 'base');
            $this->app->booted(function () use ($router): void {
                BfcProbeState::$bootedMutations++;
                self::configureWebGroup($router, self::targetShape());
            });

            return;
        }

        self::configureWebGroup(
            $router,
            str_starts_with($scenario, 'runtime-') || $scenario === 'late' ? 'base' : self::targetShape(),
        );
    }

    public static function configureWebGroup(Router $router, string $shape, bool $includeLate = true): void
    {
        $sessionMiddleware = match ($shape) {
            'zero' => [],
            'custom' => [BfcProbeStartSession::class],
            'duplicate' => [StartSession::class, BfcProbeStartSession::class],
            default => [StartSession::class],
        };
        $middleware = [
            BfcProbeHostMiddleware::class.':early',
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            ...$sessionMiddleware,
            ShareErrorsFromSession::class,
        ];

        if ($includeLate) {
            $middleware[] = BfcProbeHostMiddleware::class.':late';
        }

        $middleware[] = PreventRequestForgery::class;
        $router->middlewareGroup('web', $middleware);
    }

    public static function scenario(): string
    {
        return $_SERVER['BFC_SESSION_SCENARIO'] ?? '';
    }

    public static function targetShape(): string
    {
        $scenario = self::scenario();

        if ($scenario === 'late') {
            return 'base';
        }

        return str_contains($scenario, '-') ? substr($scenario, strrpos($scenario, '-') + 1) : $scenario;
    }
}

$scenario = $argv[1] ?? '';
$scenarios = [
    'late',
    'base',
    'custom',
    'booted-base',
    'booted-custom',
    'booted-zero',
    'booted-duplicate',
    'runtime-custom',
    'runtime-zero',
    'runtime-duplicate',
    'runtime-cache-custom',
    'runtime-priority-custom',
    'disabled',
];

if (! in_array($scenario, $scenarios, true)) {
    fwrite(STDERR, "Unknown session-stack probe.\n");
    exit(2);
}

$_SERVER['BFC_SESSION_SCENARIO'] = $scenario;

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcProbeHostProvider::class];
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
        $kernel = $this->app->make(KernelContract::class);
        $scenario = BfcProbeHostProvider::scenario();

        if ($scenario === 'runtime-cache-custom') {
            $route = $router->getRoutes()->getByName('bfc.password.reset');
            $router->gatherRouteMiddleware($route);
            $route->middleware(BfcProbeCachedRouteMiddleware::class);
            $route->computedMiddleware = null;
        }

        // Testbench resynchronizes its kernel groups after application boot. Reapply the
        // already-selected host shape so the request sees the same final group a host keeps.
        BfcProbeHostProvider::configureWebGroup($router, BfcProbeHostProvider::targetShape());

        if ($scenario === 'runtime-priority-custom') {
            array_unshift($router->middlewarePriority, PreventBearerUrlPersistence::class);
            $router->middlewarePriority[] = RestoreBearerRequestClassification::class;
        }

        $this->artisan('migrate:fresh', ['--force' => true])->run();

        if ($scenario === 'disabled') {
            $this->app->instance('middleware.disable', true);
        }
        $bearers = ['probe-reset-token', 'probe-invitation-token'];
        $observedWrites = [];
        $readingWrite = false;

        DB::listen(static function (QueryExecuted $query) use (&$observedWrites, &$readingWrite, $bearers): void {
            if ($readingWrite
                || preg_match('/^(insert into|update) ["`]?sessions["`]?/i', ltrim($query->sql)) !== 1) {
                return;
            }

            $readingWrite = true;

            try {
                $decodedAll = true;
                $bearerMatches = 0;

                foreach ($query->connection->table('sessions')->pluck('payload') as $payload) {
                    $decoded = base64_decode((string) $payload, true);
                    $decodedAll = $decodedAll && is_string($decoded);

                    foreach ($bearers as $bearer) {
                        $bearerMatches += (int) (is_string($decoded) && str_contains($decoded, $bearer));
                    }
                }

                $observedWrites[] = [
                    'decoded' => $decodedAll,
                    'bearer_matches' => $bearerMatches,
                    'transaction_level' => $query->connection->transactionLevel(),
                ];
            } finally {
                $readingWrite = false;
            }
        });

        $targetShape = $scenario === 'disabled' ? 'zero' : BfcProbeHostProvider::targetShape();
        $resolved = $targetShape === 'custom'
            ? $this->app->make(BfcProbeStartSession::class)
            : $this->app->make(StartSession::class);
        $consumer = $targetShape === 'custom'
            ? $this->app->make(BfcProbeCustomConsumer::class)
            : $this->app->make(BfcProbeBaseConsumer::class);
        $routes = $targetShape === 'zero' || $targetShape === 'duplicate'
            ? ['/bfc/reset-password/probe-reset-token']
            : [
                '/bfc/login',
                '/bfc/reset-password/probe-reset-token',
                '/bfc/invitations/probe-invitation-token',
            ];
        $responses = [];

        foreach ($routes as $path) {
            $request = Request::create($path, 'GET');
            $response = $kernel->handle($request);
            $responses[] = [
                'status' => $response->getStatusCode(),
                'exception' => $response->exception?->getMessage(),
                'early' => $response->headers->get('X-Bfc-Host-early'),
                'late' => $response->headers->get('X-Bfc-Host-late'),
                'custom' => $response->headers->get('X-Bfc-Custom-Session'),
                'cached' => $response->headers->get('X-Bfc-Cached-Route'),
            ];
            $kernel->terminate($request, $response);
        }

        $sessionClasses = [];
        $resolvedMiddleware = [];

        foreach (['bfc.password.reset', 'bfc.invitations.accept'] as $name) {
            $route = $router->getRoutes()->getByName($name);
            $resolvedMiddleware[$name] = $router->gatherRouteMiddleware($route);
            $sessionClasses[$name] = array_values(array_filter(
                $resolvedMiddleware[$name],
                static fn (mixed $middleware): bool => is_string($middleware)
                    && is_a(explode(':', $middleware, 2)[0], StartSession::class, true),
            ));
        }

        return [
            'responses' => $responses,
            'session_classes' => $sessionClasses,
            'resolved_middleware' => $resolvedMiddleware,
            'resolved_class' => $resolved::class,
            'resolved_is_requested_type' => $targetShape === 'custom'
                ? $resolved instanceof BfcProbeStartSession
                : $resolved instanceof StartSession,
            'consumer_is_requested_type' => $targetShape === 'custom'
                ? $consumer->starter instanceof BfcProbeStartSession
                : $consumer->starter instanceof StartSession,
            'custom_identity_preserved' => $targetShape !== 'custom' || $consumer->starter === $resolved,
            'custom_api' => $resolved instanceof BfcProbeStartSession ? $resolved->probeApi() : null,
            'custom_builds' => BfcProbeState::$customBuilds,
            'custom_requests' => BfcProbeState::$customRequests,
            'custom_terminates' => BfcProbeState::$customTerminates,
            'custom_normal_terminates' => BfcProbeState::$customNormalTerminates,
            'provider_boots' => BfcProbeState::$providerBoots,
            'booted_mutations' => BfcProbeState::$bootedMutations,
            'host_requests' => BfcProbeState::$hostRequests,
            'cached_route_requests' => BfcProbeState::$cachedRouteRequests,
            'observed_writes' => $observedWrites,
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

$targetShape = $scenario === 'disabled' ? 'zero' : BfcProbeHostProvider::targetShape();

if ($targetShape === 'zero' || $targetShape === 'duplicate') {
    $expected = $targetShape === 'zero' ? 0 : 2;
    $response = $result['responses'][0] ?? [];
    $valid = ($response['status'] ?? null) === 500
        && str_contains((string) ($response['exception'] ?? ''), 'bfc.password.reset')
        && str_contains((string) ($response['exception'] ?? ''), "found {$expected}")
        && $result['custom_requests'] === 0
        && $result['host_requests'] === []
        && $result['observed_writes'] === [];

    if (! $valid) {
        fwrite(STDERR, "The {$scenario} session-stack probe did not fail before middleware or persistence: ".json_encode($result)."\n");
        exit(1);
    }

    fwrite(STDOUT, ($response['exception'] ?? '').PHP_EOL);
    exit(0);
}

$responses = $result['responses'];
$expectedSessionClass = $targetShape === 'custom' ? BfcProbeStartSession::class : StartSession::class;
$valid = count($responses) === 3
    && $result['provider_boots'] === 1
    && $result['resolved_class'] === $expectedSessionClass
    && $result['resolved_is_requested_type']
    && $result['consumer_is_requested_type'];

foreach ($responses as $response) {
    $valid = $valid
        && $response['status'] === 200
        && $response['early'] === 'original-original'
        && $response['late'] === 'original-original';
}

foreach ($result['session_classes'] as $sessionClasses) {
    $valid = $valid && $sessionClasses === [$expectedSessionClass];
}

foreach ($result['resolved_middleware'] as $middleware) {
    $sessionIndex = array_search($expectedSessionClass, $middleware, true);
    $valid = $valid
        && is_int($sessionIndex)
        && ($middleware[$sessionIndex - 1] ?? null) === RestoreBearerRequestClassification::class
        && ($middleware[$sessionIndex + 1] ?? null) === PreventBearerUrlPersistence::class;
}

$valid = $valid
    && count($result['observed_writes']) === 3
    && array_column($result['observed_writes'], 'decoded') === [true, true, true]
    && array_column($result['observed_writes'], 'bearer_matches') === [0, 0, 0]
    && array_column($result['observed_writes'], 'transaction_level') === [0, 0, 0];

if ($targetShape === 'custom') {
    $valid = $valid
        && $result['custom_builds'] === 1
        && $result['custom_identity_preserved']
        && $result['custom_api'] === 'custom-api'
        && $result['custom_requests'] === 3
        && $result['custom_terminates'] === 3
        && $result['custom_normal_terminates'] === 3
        && array_column($responses, 'custom') === ['normal', 'prefetch', 'prefetch'];
}

if (str_starts_with($scenario, 'booted-')) {
    $valid = $valid && $result['booted_mutations'] === 1;
}

if ($scenario === 'runtime-cache-custom') {
    $valid = $valid
        && $result['cached_route_requests'] === 1
        && $responses[1]['cached'] === 'ran';
}

if (! $valid) {
    fwrite(STDERR, "The {$scenario} session-stack probe did not preserve the expected middleware lifecycle: ".json_encode($result)."\n");
    exit(1);
}

fwrite(STDOUT, $scenario === 'late' ? "late-host-web-ok\n" : "{$scenario}-session-ok\n");
