<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActorProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;

uses(RefreshDatabase::class);

/**
 * FLEET-C-14: the package registers the delegated guard and its provider
 * ITSELF. This Testbench app defines nothing in `auth.php` beyond
 * Testbench's own defaults — no `bfc-console` guard, no
 * `bfc-console-actors` provider — and the guard still resolves.
 *
 * The not-overwritten half lives in ConsoleGuardNotOverwrittenTest,
 * which has to set its config before the provider registers and is
 * therefore PHPUnit-style.
 */
it('registers the bfc-console guard and its provider without the app configuring anything', function (): void {
    expect(config('auth.guards.'.ConsoleGuardConfiguration::GUARD))
        ->toBe(['driver' => ConsoleGuardConfiguration::DRIVER, 'provider' => ConsoleGuardConfiguration::PROVIDER])
        ->and(config('auth.providers.'.ConsoleGuardConfiguration::PROVIDER))
        ->toBe(['driver' => ConsoleGuardConfiguration::PROVIDER]);
});

it('resolves the package guard, backed by the delegated actor provider', function (): void {
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard)->toBeInstanceOf(ConsoleGuard::class)
        ->and($guard->check())->toBeFalse()
        ->and($guard->id())->toBeNull()
        ->and(Auth::createUserProvider(ConsoleGuardConfiguration::PROVIDER))
        ->toBeInstanceOf(DelegatedActorProvider::class);
});

it('is a plain Guard and deliberately not a StatefulGuard', function (): void {
    // The whole credential-shaped half of the auth contract is absent
    // rather than disabled: no attempt(), no loginUsingId(), no
    // viaRemember(). See ConsoleGuard's docblock — §4.3's "no login
    // path" is a property of the type, not of six methods that throw.
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard)->toBeInstanceOf(Guard::class)
        ->and($guard)->not->toBeInstanceOf(StatefulGuard::class);
});

it('leaves the credential guard driver alone', function (): void {
    // The `bfc` driver and `credentials.guard` default are the FIRST
    // guard and are untouched by the Console's second, session-based one.
    expect(config('built-for-cloud.credentials.guard'))->toBe('bfc');

    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    expect(auth('bfc'))->toBeInstanceOf(CredentialGuard::class);
});

it('advertises the console-guard capability only while the console is enabled', function (): void {
    expect($this->getJson('/bfc/meta')->assertOk()->json('capabilities'))
        ->toContain('console-guard');

    // The capability describes THIS DEPLOYMENT, not the package: with
    // the flag off none of the machinery is registered, so claiming it
    // would be a lie to whatever control plane reads /bfc/meta.
    config(['built-for-cloud.console.enabled' => false]);

    expect($this->getJson('/bfc/meta')->assertOk()->json('capabilities'))
        ->not->toContain('console-guard')
        ->toContain('console-keys');
});

// ─── A reserved-provider-name collision fails boot loudly ───────────────────

it('fails loudly when the app has taken the reserved provider name', function (): void {
    $config = new Repository([
        'built-for-cloud' => ['console' => ['enabled' => true]],
        'auth' => [
            'guards' => ['web' => ['driver' => 'session', 'provider' => 'users']],
            'providers' => [
                'users' => ['driver' => 'eloquent', 'model' => User::class],
                ConsoleGuardConfiguration::PROVIDER => ['driver' => 'eloquent', 'model' => User::class],
            ],
        ],
    ]);

    expect(fn () => ConsoleGuardConfiguration::apply($config))
        ->toThrow(RuntimeException::class, 'is reserved by built-for-cloud');

    // ...and it did NOT quietly build the delegated guard on top of it.
    expect($config->get('auth.guards.'.ConsoleGuardConfiguration::GUARD))->toBeNull();
});

it('fails at boot, not merely in the helper, when the reserved provider name is taken', function (): void {
    config()->set('auth.guards.'.ConsoleGuardConfiguration::GUARD, null);
    config()->set('auth.providers.'.ConsoleGuardConfiguration::PROVIDER, [
        'driver' => 'eloquent',
        'model' => User::class,
    ]);

    // boot() is the path that calls the helper — deliberately boot and
    // not register, so an app's own config/auth.php is fully loaded
    // before the package decides whether it defined a guard. A real
    // application would take this exception during bootstrap.
    expect(fn () => (new BuiltForCloudServiceProvider(app()))->boot())
        ->toThrow(RuntimeException::class, 'is reserved by built-for-cloud');
});

// ─── A collision must not break a deployment that never asked ───────────────

it('does nothing at all — collision included — when the console is disabled', function (): void {
    $config = new Repository([
        'built-for-cloud' => ['console' => ['enabled' => false]],
        'auth' => [
            'guards' => [],
            'providers' => [
                // Exactly the collision that fails loudly when the
                // Console IS enabled.
                ConsoleGuardConfiguration::PROVIDER => ['driver' => 'eloquent', 'model' => User::class],
            ],
        ],
    ]);

    ConsoleGuardConfiguration::apply($config);

    expect($config->get('auth.guards.'.ConsoleGuardConfiguration::GUARD))->toBeNull()
        ->and($config->get('auth.providers.'.ConsoleGuardConfiguration::PROVIDER))
        ->toBe(['driver' => 'eloquent', 'model' => User::class]);
});

it('does not brick boot on a collision when the console is disabled', function (): void {
    config()->set('built-for-cloud.console.enabled', false);
    config()->set('auth.guards.'.ConsoleGuardConfiguration::GUARD, null);
    config()->set('auth.providers.'.ConsoleGuardConfiguration::PROVIDER, [
        'driver' => 'eloquent',
        'model' => User::class,
    ]);

    // An upgrade must never turn a package the app has not opted into
    // in to a boot failure for every HTTP request and artisan command.
    (new BuiltForCloudServiceProvider(app()))->boot();

    expect(config('auth.guards.'.ConsoleGuardConfiguration::GUARD))->toBeNull();
});

it('accepts the reserved provider name when the app names the package driver on it', function (): void {
    $config = new Repository([
        'built-for-cloud' => ['console' => ['enabled' => true]],
        'auth' => [
            'guards' => [],
            'providers' => [
                ConsoleGuardConfiguration::PROVIDER => ['driver' => ConsoleGuardConfiguration::PROVIDER],
            ],
        ],
    ]);

    ConsoleGuardConfiguration::apply($config);

    expect($config->get('auth.guards.'.ConsoleGuardConfiguration::GUARD))
        ->toBe(['driver' => ConsoleGuardConfiguration::DRIVER, 'provider' => ConsoleGuardConfiguration::PROVIDER]);
});

it('steps aside entirely when the app defined its own delegated guard, collision or not', function (): void {
    // The app owns both halves. The package injects nothing and throws
    // nothing: the not-overwritten rule wins over the collision rule,
    // because there is no package guard about to be built on the
    // hijacked name.
    $config = new Repository([
        'built-for-cloud' => ['console' => ['enabled' => true]],
        'auth' => [
            'guards' => [
                ConsoleGuardConfiguration::GUARD => ['driver' => 'session', 'provider' => ConsoleGuardConfiguration::PROVIDER],
            ],
            'providers' => [
                ConsoleGuardConfiguration::PROVIDER => ['driver' => 'eloquent', 'model' => User::class],
            ],
        ],
    ]);

    ConsoleGuardConfiguration::apply($config);

    expect($config->get('auth.guards.'.ConsoleGuardConfiguration::GUARD))
        ->toBe(['driver' => 'session', 'provider' => ConsoleGuardConfiguration::PROVIDER])
        ->and($config->get('auth.providers.'.ConsoleGuardConfiguration::PROVIDER))
        ->toBe(['driver' => 'eloquent', 'model' => User::class]);
});
