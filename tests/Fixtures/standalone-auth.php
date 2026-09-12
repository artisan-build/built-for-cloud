<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

require __DIR__.'/../../vendor/autoload.php';

$vector = $argv[1] ?? '';
$ordering = $argv[2] ?? '';

if (! in_array($vector, ['fqcn-alias', 'fqcn-group', 'fqcn-exclusion', 'alias-exclusion', 'memo-set-action', 'memo-property'], true)
    || ! in_array($ordering, ['boot', 'match'], true)) {
    fwrite(STDERR, "Unknown standalone authentication gate probe.\n");
    exit(2);
}

final class BfcStandaloneAuthGateState
{
    /** @var list<string> */
    public static array $paths = [];
}

final class BfcStandaloneAuthGatePassThrough
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        BfcStandaloneAuthGateState::$paths[] = $request->path();

        return $next($request);
    }
}

final class BfcStandaloneAuthGateHostProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $attack = static function () use ($router): void {
            $vector = $_SERVER['BFC_STANDALONE_AUTH_VECTOR'] ?? '';

            if ($vector === 'fqcn-alias') {
                $router->aliasMiddleware(EnsureUserIsAuthenticated::class, BfcStandaloneAuthGatePassThrough::class);

                return;
            }

            if ($vector === 'fqcn-group') {
                $router->middlewareGroup(EnsureUserIsAuthenticated::class, [BfcStandaloneAuthGatePassThrough::class]);

                return;
            }

            if (in_array($vector, ['memo-set-action', 'memo-property'], true)) {
                foreach ($router->getRoutes() as $route) {
                    if (! in_array(EnsureUserIsAuthenticated::class, $route->middleware(), true)) {
                        continue;
                    }

                    $gateless = array_values(array_filter(
                        $route->middleware(),
                        static fn (mixed $middleware): bool => $middleware !== EnsureUserIsAuthenticated::class,
                    ));

                    if ($vector === 'memo-property') {
                        $route->computedMiddleware = $gateless;

                        continue;
                    }

                    $action = $route->getAction();
                    $stripped = $action;
                    $stripped['middleware'] = $gateless;
                    $route->setAction($stripped);
                    $route->gatherMiddleware();
                    $route->setAction($action);
                }

                return;
            }

            $exclusion = $vector === 'fqcn-exclusion'
                ? EnsureUserIsAuthenticated::class
                : 'bfc.auth';

            foreach ($router->getRoutes() as $route) {
                if (in_array(EnsureUserIsAuthenticated::class, $route->middleware(), true)) {
                    $route->withoutMiddleware($exclusion);
                }
            }
        };

        if (($_SERVER['BFC_STANDALONE_AUTH_ORDERING'] ?? '') === 'boot') {
            $attack();

            return;
        }

        $this->app->booted($attack);
    }
}

$_SERVER['BFC_STANDALONE_AUTH_VECTOR'] = $vector;
$_SERVER['BFC_STANDALONE_AUTH_ORDERING'] = $ordering;

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcStandaloneAuthGateHostProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('g', 32)));
    }

    public function runProbe(): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        Notification::fake();

        /** @var Router $router */
        $router = $this->app['router'];
        $routes = array_values(array_filter(
            $router->getRoutes()->getRoutes(),
            static fn (Route $route): bool => in_array(EnsureUserIsAuthenticated::class, $route->middleware(), true)
                && ! str_starts_with((string) $route->getName(), 'bfc.transitions.'),
        ));

        if (count($routes) !== 11) {
            fwrite(STDERR, 'standalone-auth-route-count-'.count($routes).PHP_EOL);

            return false;
        }

        $memoPoisoning = in_array($vector = $_SERVER['BFC_STANDALONE_AUTH_VECTOR'] ?? '', ['memo-set-action', 'memo-property'], true);
        $poisonedStacks = $memoPoisoning
            ? count(array_filter(
                $routes,
                static fn (Route $route): bool => ! in_array(
                    EnsureUserIsAuthenticated::class,
                    $router->gatherRouteMiddleware($route),
                    true,
                ),
            ))
            : 0;

        $member = User::query()->create([
            'name' => 'Authentication Gate Member',
            'email' => 'auth-gate-member@example.test',
            'password' => null,
        ]);
        $member->forceFill([
            'role' => UserRole::Member->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $member->email,
        ])->save();
        $credential = CredentialFactory::new()->forUser((string) $member->getKey())->create();
        $credentialCount = Credential::query()->count();

        $statuses = [];
        $disclosed = [];
        $recomputed = [];

        foreach ($routes as $route) {
            $path = '/'.str_replace(
                ['{user}', '{session}', '{id}'],
                [(string) $member->getKey(), 'auth-gate-session', (string) $credential->getKey()],
                $route->uri(),
            );
            $response = $this->call($route->methods()[0], $path, [
                'email' => 'new-auth-gate-member@example.test',
                'role' => UserRole::Admin->value,
                'name' => 'auth-gate-created',
                'password' => 'not-used-before-refusal',
            ]);
            $statuses[] = $response->getStatusCode();
            $disclosed[] = str_contains($response->getContent(), (string) $member->email);
            $recomputed[] = in_array(
                EnsureUserIsAuthenticated::class,
                $router->gatherRouteMiddleware($route),
                true,
            );
        }

        Notification::assertNothingSent();

        $allRefused = $memoPoisoning
            ? count(array_filter($statuses, static fn (int $status): bool => $status < 200 || $status >= 300)) === 11
            : $statuses === array_fill(0, 11, 500);

        return $allRefused
            && (! $memoPoisoning || ($poisonedStacks === 11 && ! in_array(false, $recomputed, true)))
            && ! in_array(true, $disclosed, true)
            && BfcStandaloneAuthGateState::$paths === []
            && Invitation::query()->count() === 0
            && Credential::query()->count() === $credentialCount
            && $member->refresh()->role === UserRole::Member->value
            && $member->status === 'active';
    }

    public function test_probe(): void {}
};

try {
    $valid = $case->runProbe();
} catch (RuntimeException $exception) {
    if ($ordering === 'boot'
        && str_contains($exception->getMessage(), 'must retain its built-for-cloud package middleware')) {
        fwrite(STDOUT, "standalone-auth-gate-boot-refused\n");
        exit(0);
    }

    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if ($ordering !== 'match' || ! $valid) {
    fwrite(STDERR, "The standalone authentication gate probe failed.\n");
    exit(1);
}

if (in_array($vector, ['memo-set-action', 'memo-property'], true)) {
    fwrite(STDOUT, "standalone-auth-gate-{$vector}-refused-11\n");
} else {
    fwrite(STDOUT, "standalone-auth-gate-match-refused-11\n");
}
