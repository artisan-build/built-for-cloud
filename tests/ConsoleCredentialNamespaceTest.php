<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * The `bfc-console:` namespace is RESERVED, and no credential resolves a
 * principal through it.
 *
 * The danger is not that `bfc-console:1` might match a delegated actor —
 * it is what an ORDINARY user provider does when handed one. Against an
 * Eloquent provider over an integer key, MySQL coerces the non-numeric
 * string toward `0` and can resolve the row with key 0; PostgreSQL
 * raises; sqlite quietly matches nothing. Three drivers, three
 * behaviours, none of them a decision this package made — so the value
 * is refused BEFORE any provider is asked.
 */
beforeEach(function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    Route::middleware('auth:bfc')->get('/token-route', fn (): array => [
        'principal' => auth('bfc')->id(),
    ]);
});

function namespaceUser(string $email = 'bound@example.com'): User
{
    return User::query()->create([
        'name' => 'Bound User',
        'email' => $email,
        'password' => 'irrelevant',
    ]);
}

it('never resolves a principal for a credential bound to the reserved namespace', function (string $userId): void {
    namespaceUser();
    consoleActor();

    $minted = $this->mintCredential(['user_id' => $userId]);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);
})->with([
    'canonical' => ['bfc-console:1'],
    'trailing junk' => ['bfc-console:1junk'],
    'leading zero' => ['bfc-console:01'],
    'zero' => ['bfc-console:0'],
    'oversized' => ['bfc-console:999999999999999999999999'],
    'empty suffix' => ['bfc-console:'],
    'prefix only, different case suffix' => ['bfc-console:1 '],
]);

it('resolves an ordinary user-bound credential exactly as before', function (): void {
    $user = namespaceUser();
    consoleActor();

    $minted = $this->mintCredential(['user_id' => (string) $user->getKey()]);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('principal', $user->getKey());
});

it('refuses a bound user whose provider answered with a different identifier', function (): void {
    // A non-canonical id an integer-keyed provider might coerce: sqlite
    // matches nothing, MySQL would match user 1. Either way the round
    // trip check refuses, because the principal that came back does not
    // emit the identifier the credential stored.
    $user = namespaceUser();

    expect($user->getKey())->toBe(1);

    $minted = $this->mintCredential(['user_id' => '1junk']);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);
})->note('On sqlite the coercion does not happen, so this test pins the round-trip check rather than reproducing the MySQL behaviour it defends against. The reserved-namespace refusal above is what stops the delegated case on every driver.');

it('keeps the reserved namespace out of any user provider, whatever the bfc guard points at', function (): void {
    // The pathological configuration: the credential guard's provider IS
    // the delegated actor provider. Even then no credential resolves an
    // actor — the namespace never reaches the provider, and a returned
    // DelegatedActor would be rejected anyway.
    config(['auth.providers.console-actors' => ['driver' => 'bfc-console-actors']]);
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'console-actors']]);

    $actor = consoleActor();
    $minted = $this->mintCredential(['user_id' => $actor->getAuthIdentifier()]);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);

    expect(DelegatedActor::query()->count())->toBe(1);
});
