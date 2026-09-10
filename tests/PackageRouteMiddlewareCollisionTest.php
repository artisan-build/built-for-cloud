<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\Scope;
use Closure;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

final class HostilePackageGateMiddleware
{
    /** @var list<string> */
    public static array $paths = [];

    public function handle(Request $request, Closure $next): Response
    {
        self::$paths[] = $request->path();

        return $next($request);
    }
}

beforeEach(function (): void {
    /** @var Router $router */
    $router = app('router');

    // Materialize the kernel's aliases before the hostile host replaces
    // every package alias with both forms Laravel can resolve first.
    app(Kernel::class);

    $packageAliases = array_keys(array_filter(
        $router->getMiddleware(),
        static fn (mixed $middleware): bool => is_string($middleware)
            && str_starts_with($middleware, 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\'),
    ));

    expect($packageAliases)->not->toBe([]);

    foreach ($packageAliases as $alias) {
        $router->aliasMiddleware($alias, HostilePackageGateMiddleware::class);
        $router->middlewareGroup($alias, [HostilePackageGateMiddleware::class]);
    }

    HostilePackageGateMiddleware::$paths = [];

    $router->get('/_bfc-test/package-gate-alias-control', static fn (): string => 'host-control')
        ->middleware('bfc.token.admin');
});

/**
 * @param  iterable<Route>  $routes
 * @return array{checked: array<string, list<string>>, breaks: list<string>}
 */
function packageGateProtectionScan(Router $router, iterable $routes): array
{
    $families = [
        'bfc.token.admin' => EnsureAdminToken::class,
        'bfc.credential.admin' => EnsureCredentialAdmin::class,
        'bfc.console' => EnsureConsoleSession::class,
    ];
    $checked = [];
    $breaks = [];

    foreach ($routes as $route) {
        $expected = [];

        foreach ($route->gatherMiddleware() as $middleware) {
            if (! is_string($middleware)) {
                continue;
            }

            [$name, $parameters] = array_pad(explode(':', $middleware, 2), 2, null);

            foreach ($families as $alias => $class) {
                if ($name === $alias || $name === $class) {
                    $expected[] = $class.($parameters === null ? '' : ':'.$parameters);
                }
            }
        }

        if ($expected === []) {
            continue;
        }

        $label = implode(',', array_values(array_diff($route->methods(), ['HEAD', 'OPTIONS']))).' /'.$route->uri();
        $checked[$label] = $expected;
        $resolved = $router->resolveMiddleware($route->gatherMiddleware(), $route->excludedMiddleware());

        foreach ($expected as $gate) {
            if (! in_array($gate, $resolved, true)) {
                $breaks[] = $label.': missing '.$gate;
            }
        }
    }

    ksort($checked);
    sort($breaks);

    return ['checked' => $checked, 'breaks' => $breaks];
}

it('keeps every declared package route gate effective through hostile host alias and group collisions', function (): void {
    /** @var Router $router */
    $router = app('router');

    $packageRoutes = array_filter(
        $router->getRoutes()->getRoutes(),
        static fn (Route $route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'),
    );
    $scan = packageGateProtectionScan($router, $packageRoutes);

    expect($scan['checked'])->not->toBe([])
        ->and(array_values(array_unique(array_merge(...array_values($scan['checked'])))))->toContain(
            EnsureAdminToken::class,
            EnsureConsoleSession::class,
            EnsureCredentialAdmin::class.':credential:read',
        )
        ->and($scan['breaks'])->toBe([]);
});

it('reports an alias-bound fixture route as unprotected under the same hostile host', function (): void {
    /** @var Router $router */
    $router = app('router');
    $control = $router->getRoutes()->match(Request::create('/_bfc-test/package-gate-alias-control'));
    $scan = packageGateProtectionScan($router, [$control]);

    expect($scan['checked'])->toBe([
        'GET /_bfc-test/package-gate-alias-control' => [EnsureAdminToken::class],
    ])->and($scan['breaks'])->toBe([
        'GET /_bfc-test/package-gate-alias-control: missing '.EnsureAdminToken::class,
    ]);
});

it('refuses one route from each gate family before controller effects under the hostile host', function (): void {
    Mail::fake();
    Notification::fake();

    $owner = ApiToken::factory()->create([
        'name' => 'collision-owner',
        'abilities' => [Scope::Admin->value],
    ]);
    $ownership = Ownership::query()->create(['owner_token_id' => $owner->getKey()]);
    $tokenLookups = 0;

    DB::listen(static function (QueryExecuted $query) use (&$tokenLookups): void {
        if (str_starts_with(ltrim(strtolower($query->sql)), 'select')
            && (str_contains($query->sql, '"api_tokens"') || str_contains($query->sql, '`api_tokens`'))) {
            $tokenLookups++;
        }
    });

    $this->postJson('/bfc/ownership/release')->assertUnauthorized();
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'collision-target',
        'name' => 'collision-mint',
    ])->assertUnauthorized();
    $this->get('/bfc/console/chrome.js')
        ->assertUnauthorized()
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('error', 'console_reentry_required');

    expect($tokenLookups)->toBe(0)
        ->and($ownership->refresh()->pending_claim_id)->toBeNull()
        ->and(Credential::query()->where('name', 'collision-mint')->doesntExist())->toBeTrue()
        ->and(HostilePackageGateMiddleware::$paths)->toBe([]);

    Mail::assertNothingSent();
    Notification::assertNothingSent();
});
