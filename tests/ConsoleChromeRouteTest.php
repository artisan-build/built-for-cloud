<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Tests\ConsoleChromeRouteScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnguardedChromeController;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * AC9 — D14's two seams, over the routes this package actually
 * registers.
 *
 * The shape here is the one this build has got wrong four times: a scan
 * that FILTERS before it compares cannot see a missing thing. So the
 * scan classifies every registered route and these tests check the
 * classification is not vacuous before checking the rule, and then prove
 * the rule can fail against fixtures carrying each offence.
 */
it('requires both halves of the delegated seam on every registered chrome route', function (): void {
    $routes = Route::getRoutes()->getRoutes();

    // NOT VACUOUS: the scan found the chrome route this release mounts.
    // Without this line an empty result would read as a pass.
    expect(ConsoleChromeRouteScan::chromeRoutesIn($routes))->toBe(['GET /bfc/console/chrome.js']);

    // And every route in the package — chrome-marked or merely carrying
    // one half of the seam — carries both.
    expect(ConsoleChromeRouteScan::seamBreaksIn($routes))->toBe([]);

    // Every registered route is CLASSIFIED, so none of them left the
    // scan by being unrecognised.
    $classified = ConsoleChromeRouteScan::classify($routes);

    expect(count($classified))->toBe(count(array_unique(array_map(
        static fn ($route): string => implode(',', array_values(array_diff($route->methods(), ['HEAD', 'OPTIONS']))).' /'.$route->uri(),
        $routes,
    ))))
        ->and($classified['GET /bfc/console/chrome.js'])->toBe(ConsoleChromeRouteScan::CHROME);
});

it('names a chrome route that carries only one half of the seam, and one that carries neither', function (): void {
    // Proven able to fail, on all three shapes: no seam at all, the
    // guard scoping without the re-entry answer (the trap this brief
    // names — the operator sees nothing and their session stays alive),
    // and the re-entry answer without the guard scoping.
    Route::get('/probe-chrome-bare', UnguardedChromeController::class);

    Route::middleware([StartSession::class, 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/probe-chrome-guard-only', UnguardedChromeController::class);

    Route::middleware([StartSession::class, 'bfc.console'])
        ->get('/probe-chrome-session-only', UnguardedChromeController::class);

    // The INVERSE leg: a route nobody marked as chrome that has been
    // given one half of the seam anyway.
    Route::middleware([StartSession::class, 'bfc.console'])
        ->get('/probe-unmarked-session-only', fn (): array => ['ok' => true]);

    $breaks = ConsoleChromeRouteScan::seamBreaksIn(Route::getRoutes()->getRoutes());

    expect($breaks)->toBe([
        'GET /probe-chrome-bare: missing auth:bfc-console and bfc.console',
        'GET /probe-chrome-guard-only: missing bfc.console',
        'GET /probe-chrome-session-only: missing auth:bfc-console',
        'GET /probe-unmarked-session-only: missing auth:bfc-console',
    ]);
});

it('recognises the seam however a route spells it', function (): void {
    // The middleware class rather than the alias, and a guard list
    // rather than a single guard: both are legal spellings of the same
    // stack, and a scan that only matched one string would report a
    // conforming route as broken — or, worse, teach an author to spell
    // it the one way the scan understands.
    Route::middleware([
        StartSession::class,
        EnsureConsoleSession::class,
        Authenticate::class.':'.ConsoleGuardConfiguration::GUARD.',web',
    ])->get('/probe-chrome-spelled-out', UnguardedChromeController::class);

    // And a near miss that must NOT count: the reserved PROVIDER name is
    // not the guard name.
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::PROVIDER])
        ->get('/probe-chrome-wrong-guard', UnguardedChromeController::class);

    expect(ConsoleChromeRouteScan::seamBreaksIn(Route::getRoutes()->getRoutes()))
        ->toBe(['GET /probe-chrome-wrong-guard: missing auth:bfc-console']);
});

it('runs the re-entry answer in front of the guard scoping, after Laravel has sorted the stack', function (): void {
    // The DECLARED order is not the executed one. Laravel sorts a
    // route's middleware by priority, and `AuthenticatesRequests`
    // outranks `ThrottleRequests` — so this is asserted against the
    // router's sorted, alias-resolved stack rather than against what the
    // route was written with.
    //
    // Resolving the HTTP kernel is what makes that stack REAL: its
    // constructor is what copies the app's middleware aliases and the
    // priority list onto the router. Ask before that and the router
    // hands back the raw declaration, which is exactly the thing this
    // test must not be fooled by.
    app(Kernel::class);

    expect(ConsoleChromeRouteScan::orderBreaksIn(app('router'), Route::getRoutes()->getRoutes()))->toBe([]);

    // And end to end, which is the thing the order is FOR: a request
    // with no delegated session gets D7's structured 401, not the
    // framework's own answer.
    $this->get('/bfc/console/chrome.js')
        ->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('error', 'console_reentry_required');
});

it('names a route whose throttle hoists the guard scoping in front of the re-entry answer', function (): void {
    // Proven able to fail, on the exact defect this PR shipped and then
    // fixed: the throttle declared OUTERMOST, which is the convention
    // every other route in this package follows, makes Laravel hoist
    // `auth:bfc-console` above `bfc.console`.
    app(Kernel::class);

    Route::middleware([
        'throttle:bfc-console-chrome',
        StartSession::class,
        'bfc.console',
        'auth:'.ConsoleGuardConfiguration::GUARD,
    ])->get('/probe-chrome-hoisted', UnguardedChromeController::class);

    expect(ConsoleChromeRouteScan::seamBreaksIn(Route::getRoutes()->getRoutes()))->toBe([])
        ->and(ConsoleChromeRouteScan::orderBreaksIn(app('router'), Route::getRoutes()->getRoutes()))
        ->toBe(['GET /probe-chrome-hoisted: the guard scoping runs before the re-entry answer']);
});

it('accounts for every file in src that names a package view', function (): void {
    $src = dirname(__DIR__).'/src';

    // The second leg. The marker interface is a convention, so a
    // controller that renders the chrome without implementing it would
    // be classified as unrelated and pass the route rule above. This
    // enumerates the files that actually reach for a `bfc::` view, and
    // the expected set is short enough to read: the provider, which
    // registers the namespace and the layout's composer, and nothing
    // else. A new file rendering the layout reds this until somebody
    // says why.
    expect(ConsoleChromeRouteScan::countPhpFiles($src))->toBeGreaterThan(100);

    expect(ConsoleChromeRouteScan::viewReferencesIn($src))
        ->toBe([basename((string) (new ReflectionClass(BuiltForCloudServiceProvider::class))->getFileName())]);
});

it('serves the interceptor to a delegated session and the structured 401 to nobody', function (): void {
    // The route is real, not merely enumerated: a live delegated session
    // gets the script, and a request with none gets the re-entry 401
    // rather than a script or a framework redirect.
    $this->get('/bfc/console/chrome.js')
        ->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('reason', 'not_authenticated');

    $actor = consoleActor();

    $response = $this->withSession(consoleSessionState($actor))->get('/bfc/console/chrome.js')->assertOk();

    expect($response->headers->get('Content-Type'))->toBe('text/javascript; charset=utf-8')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->getContent())->toBe(file_get_contents(ConsoleChromeScript::SOURCE));
});
