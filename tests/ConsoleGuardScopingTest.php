<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * HOW THE DELEGATED PRINCIPAL IS SCOPED TO A ROUTE, and the runtime
 * assumption that makes it safe. Ed's ruling, 2026-08-29: keep the stock
 * `auth:bfc-console` middleware; do not hand-roll a second solution to a
 * framework concern.
 *
 * THE FACT THIS FILE EXISTS TO PIN. `auth:bfc-console` is Laravel's own
 * {@see Authenticate}, and it calls
 * `AuthManager::shouldUse($guard)` → `setDefaultDriver()` →
 * `$app['config']['auth.defaults.guard'] = 'bfc-console'`. That write is
 * REAL and it is process-global for the life of the config repository.
 * It is exactly what `auth:web` and `auth:api` do in every Laravel
 * application, and this package adds nothing to it — but "the framework
 * does it too" is not a safety argument, so the conditions under which
 * it does and does not leak are asserted here rather than described.
 *
 * WHAT CLOSES IT, on the two runtimes this package ships on:
 *
 *  - **PHP-FPM** — a fresh process per request. Nothing to leak into.
 *  - **Octane** — `Laravel\Octane\Listeners\CreateConfigurationSandbox`,
 *    which runs on every `RequestReceived` (it is in
 *    `Octane::prepareApplicationForNextOperation()`) and does
 *    `$sandbox->instance('config', clone $sandbox['config'])`.
 *    `Illuminate\Config\Repository::$items` is a plain array and `set()`
 *    writes into it, so PHP's value semantics mean a write to the clone
 *    cannot reach the repository it was cloned from. Octane also takes
 *    the sandbox itself from a fresh `clone $this->app` per request, so
 *    the clone is made from the pristine base repository rather than
 *    from the previous request's mutated one.
 *
 * WHAT DOES **NOT** CLOSE IT, and this is the part an auditor gets wrong:
 * `Laravel\Octane\Listeners\FlushAuthenticationState`. It is the listener
 * whose name says it handles this, it runs on the same event, and it does
 * `forgetInstance('auth.driver')`, `setApplication($sandbox)` and
 * `AuthManager::forgetGuards()` — which is literally `$this->guards = [];`.
 * **It never touches config.** The first test below asserts that directly,
 * so nobody re-derives the guarantee from the wrong listener.
 *
 * THE RUNTIME ASSUMPTION, stated plainly because it is the condition
 * under which this becomes a real privilege leak: **any runtime that
 * reuses a container across requests WITHOUT sandboxing the config
 * repository leaves `auth.defaults.guard` pointed at the console guard
 * for every later request in that process.** On such a runtime a request
 * that touches no Console route would resolve its principal through the
 * delegated guard. This package cannot detect or prevent that from
 * inside a guard; it is a property of the host runtime, and it is why
 * the mechanism is named here rather than assumed.
 *
 * THIS SUITE IS ITSELF SUCH A CONTEXT. Testbench reuses one container
 * across the requests in a test method and clones no config, which is
 * what makes both halves below directly assertable: the leak is shown to
 * be real, and the sandbox is shown to be what closes it.
 */
beforeEach(function (): void {
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/scoping-console', fn (): array => [
            'principal' => app(ActingPrincipalResolver::class)->resolve()->identifier(),
        ]);

    Route::middleware([StartSession::class])->get('/scoping-app', fn (): array => [
        'principal' => app(ActingPrincipalResolver::class)->resolve()->identifier(),
        'guard' => app(ActingPrincipalResolver::class)->resolve()->guard,
        'default_guard' => config('auth.defaults.guard'),
    ]);
});

function scopingUser(): User
{
    return User::query()->create([
        'name' => 'Local User',
        'email' => 'local@example.com',
        'password' => 'irrelevant',
    ]);
}

// ─── The write is real, and the auth flush is NOT what closes it ────────────

it('leaves auth.defaults.guard pointed at the console guard, and forgetting guards does not put it back', function (): void {
    $actor = consoleActor();

    expect(config('auth.defaults.guard'))->toBe('web');

    $this->withSession(consoleSessionState($actor));
    $this->getJson('/scoping-console')->assertOk();

    // Laravel's own Authenticate middleware wrote it. Nothing in this
    // package did — ConsoleActingPrincipalTest scans src/ for that.
    expect(config('auth.defaults.guard'))->toBe(ConsoleGuardConfiguration::GUARD);

    // THE WHOLE POINT OF THIS ASSERTION: this is the entirety of what
    // Octane's FlushAuthenticationState does to the auth stack —
    // AuthManager::forgetGuards() is `$this->guards = [];`. The config
    // value survives it untouched. An auditor who checks that listener
    // and concludes the leak is closed has checked the wrong one.
    Auth::forgetGuards();

    expect(config('auth.defaults.guard'))->toBe(ConsoleGuardConfiguration::GUARD);
});

it('would resolve a non-console route through the delegated guard on a runtime that never sandboxes config', function (): void {
    // The hazard, made concrete rather than described. This is a
    // container reused across requests with no config sandbox — the
    // stated runtime assumption, violated — and the consequence is a
    // route that never mentioned the Console resolving its principal
    // through the delegated guard.
    //
    // It is asserted so that the guarantee below reads as a dependency
    // on the sandbox rather than as luck, and so that a future change
    // which quietly starts relying on this state has something to break.
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor));
    $this->getJson('/scoping-console')->assertOk();

    Auth::forgetGuards();

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/scoping-app')
        ->assertOk()
        ->assertJsonPath('default_guard', ConsoleGuardConfiguration::GUARD)
        ->assertJsonPath('guard', ConsoleGuardConfiguration::GUARD);
});

// ─── The config sandbox is what closes it ───────────────────────────────────

it('does not leak into the next request when the config repository is cloned per request, as Octane clones it', function (): void {
    $user = scopingUser();
    $actor = consoleActor();

    /** @var Repository $pristine */
    $pristine = app('config');

    expect($pristine->get('auth.defaults.guard'))->toBe('web');

    // Request A, inside a config sandbox — the same operation
    // Laravel\Octane\Listeners\CreateConfigurationSandbox performs on
    // every RequestReceived: the repository the request will mutate is a
    // CLONE, and Repository::$items is a plain array, so the write
    // cannot reach the original.
    app()->instance('config', clone $pristine);

    $this->withSession(consoleSessionState($actor));
    $this->getJson('/scoping-console')
        ->assertOk()
        ->assertJsonPath('principal', $actor->getAuthIdentifier());

    // The clone took the write...
    expect(config('auth.defaults.guard'))->toBe(ConsoleGuardConfiguration::GUARD)
        // ...and the repository the NEXT clone is taken from did not.
        // This is the whole guarantee, in one assertion.
        ->and($pristine->get('auth.defaults.guard'))->toBe('web');

    // Request B, its own sandbox taken from the pristine repository, on
    // a route that never mentions the Console.
    app()->instance('config', clone $pristine);
    Auth::forgetGuards();

    $this->actingAs($user);

    $this->getJson('/scoping-app')
        ->assertOk()
        ->assertJsonPath('default_guard', 'web')
        ->assertJsonPath('guard', 'web')
        ->assertJsonPath('principal', $user->getKey());
});

it('isolates a config write to the clone, which is the property the whole guarantee rests on', function (): void {
    // Stated as a property of Illuminate\Config\Repository rather than
    // of this package, because that is what it is — and because if a
    // future Laravel gave Repository a __clone() that shared state, or
    // moved $items behind an object, everything above would silently
    // stop being true while still passing a request-level test.
    $pristine = new Repository(['auth' => ['defaults' => ['guard' => 'web']]]);

    $sandbox = clone $pristine;
    $sandbox->set('auth.defaults.guard', ConsoleGuardConfiguration::GUARD);

    expect($sandbox->get('auth.defaults.guard'))->toBe(ConsoleGuardConfiguration::GUARD)
        ->and($pristine->get('auth.defaults.guard'))->toBe('web');
});
