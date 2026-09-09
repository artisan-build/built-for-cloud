<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
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

    public static int $customBuilds = 0;

    public static int $customRequests = 0;
}

final class BfcProbeStartSession extends StartSession
{
    public function handle($request, Closure $next)
    {
        BfcProbeState::$customRequests++;
        $response = parent::handle($request, $next);
        $response->headers->set('X-Bfc-Custom-Session', $request->prefetch() ? 'prefetch' : 'normal');

        return $response;
    }
}

final class BfcProbeHostMiddleware
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next, string $position): Response
    {
        $inbound = $request->isMethod('GET') && ! $request->prefetch() ? 'original' : 'changed';
        $response = $next($request);
        $unwind = $request->isMethod('GET') && ! $request->prefetch() ? 'original' : 'changed';
        $response->headers->set("X-Bfc-Host-{$position}", $inbound.'-'.$unwind);

        return $response;
    }
}

final class BfcProbeHostProvider extends ServiceProvider
{
    public function register(): void
    {
        if (($_SERVER['BFC_SESSION_SHAPE'] ?? '') === 'custom'
            || ($_SERVER['BFC_SESSION_SHAPE'] ?? '') === 'duplicate') {
            $this->app->singleton(BfcProbeStartSession::class, function (Application $app): BfcProbeStartSession {
                BfcProbeState::$customBuilds++;

                return new BfcProbeStartSession(
                    $app->make(SessionManager::class),
                    static fn (): CacheFactory => $app->make(CacheFactory::class),
                );
            });
        }

        self::configureWebGroup($this->app['router'], includeLate: false);
    }

    public function boot(Router $router): void
    {
        BfcProbeState::$providerBoots++;
        self::configureWebGroup($router);
    }

    public static function configureWebGroup(Router $router, bool $includeLate = true): void
    {
        $shape = $_SERVER['BFC_SESSION_SHAPE'] ?? '';
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
            PreventRequestForgery::class,
        ];

        if ($includeLate && $shape === 'late') {
            $middleware[] = BfcProbeHostMiddleware::class.':late';
        }

        $router->middlewareGroup('web', $middleware);
    }
}

$shape = $argv[1] ?? '';

if (! in_array($shape, ['late', 'base', 'custom', 'zero', 'duplicate'], true)) {
    fwrite(STDERR, "Unknown session-stack probe.\n");
    exit(2);
}

$_SERVER['BFC_SESSION_SHAPE'] = $shape;

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
        $app['config']->set('session.driver', ($_SERVER['BFC_SESSION_SHAPE'] ?? '') === 'custom' ? 'database' : 'array');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('s', 32)));
    }

    /** @return array<string, mixed> */
    public function runProbe(): array
    {
        parent::setUp();
        $kernel = $this->app->make(KernelContract::class);

        $this->artisan('migrate:fresh', ['--force' => true])->run();
        BfcProbeHostProvider::configureWebGroup($this->app['router']);
        $observedWrites = [];
        $readingWrite = false;

        if (($_SERVER['BFC_SESSION_SHAPE'] ?? '') === 'custom') {
            DB::listen(static function (QueryExecuted $query) use (&$observedWrites, &$readingWrite): void {
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

                        foreach (['probe-reset-token', 'probe-invitation-token'] as $bearer) {
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
        }
        $routes = [
            '/bfc/login',
            '/bfc/reset-password/probe-reset-token',
            '/bfc/invitations/probe-invitation-token',
        ];
        $responses = [];

        foreach ($routes as $route) {
            $request = Request::create($route, 'GET');
            $response = $kernel->handle($request);

            if ($response->getStatusCode() !== 200) {
                $exception = $response->exception;
                $detail = $exception instanceof Throwable ? ' '.$exception::class.': '.$exception->getMessage() : '';

                throw new RuntimeException("Probe route [{$route}] returned status {$response->getStatusCode()}.{$detail}");
            }
            $responses[] = [
                'early' => $response->headers->get('X-Bfc-Host-early'),
                'late' => $response->headers->get('X-Bfc-Host-late'),
                'custom' => $response->headers->get('X-Bfc-Custom-Session'),
            ];
            $kernel->terminate($request, $response);
        }

        /** @var Router $router */
        $router = $this->app['router'];
        $sessionClasses = [];
        $resolvedMiddleware = [];

        foreach (['bfc.password.reset', 'bfc.invitations.accept'] as $name) {
            $route = $router->getRoutes()->getByName($name);

            if ($route === null) {
                throw new RuntimeException("Probe route [{$name}] was not registered.");
            }
            $sessionClasses[$name] = array_values(array_filter(
                $resolvedMiddleware[$name] = $router->gatherRouteMiddleware($route),
                static fn (mixed $middleware): bool => is_string($middleware)
                    && is_a($middleware, StartSession::class, true),
            ));
        }

        return [
            'responses' => $responses,
            'session_classes' => $sessionClasses,
            'resolved_middleware' => $resolvedMiddleware,
            'custom_builds' => BfcProbeState::$customBuilds,
            'custom_requests' => BfcProbeState::$customRequests,
            'provider_boots' => BfcProbeState::$providerBoots,
            'observed_writes' => $observedWrites,
        ];
    }

    public function test_probe(): void {}
};

try {
    $result = $case->runProbe();
} catch (LogicException $exception) {
    $expected = match ($shape) {
        'zero' => 0,
        'duplicate' => 2,
        default => null,
    };

    if ($expected !== null
        && str_contains($exception->getMessage(), 'bfc.password.reset')
        && str_contains($exception->getMessage(), "found {$expected}")) {
        fwrite(STDOUT, $exception->getMessage().PHP_EOL);
        exit(0);
    }

    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if ($shape === 'zero' || $shape === 'duplicate') {
    fwrite(STDERR, "The invalid {$shape} session stack booted unexpectedly.\n");
    exit(1);
}

$responses = $result['responses'];
$expectedSessionClass = $shape === 'custom' ? BfcProbeStartSession::class : StartSession::class;
$valid = count($responses) === 3;

foreach ($responses as $response) {
    $valid = $valid
        && $response['early'] === 'original-original'
        && ($shape !== 'late' || $response['late'] === 'original-original');
}

foreach ($result['session_classes'] as $sessionClasses) {
    $valid = $valid && $sessionClasses === [$expectedSessionClass];
}

if ($shape === 'custom') {
    $valid = $valid
        && $result['custom_builds'] === 1
        && $result['custom_requests'] === 3
        && array_column($responses, 'custom') === ['normal', 'prefetch', 'prefetch']
        && count($result['observed_writes']) === 3
        && array_column($result['observed_writes'], 'decoded') === [true, true, true]
        && array_column($result['observed_writes'], 'bearer_matches') === [0, 0, 0]
        && array_column($result['observed_writes'], 'transaction_level') === [0, 0, 0];
}

if (! $valid) {
    fwrite(STDERR, "The {$shape} session-stack probe did not preserve the expected middleware lifecycle: ".json_encode($result)."\n");
    exit(1);
}

fwrite(STDOUT, $shape === 'late' ? "late-host-web-ok\n" : "{$shape}-session-ok\n");
