<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, WithCredentials::class, DetectsSecretLeaks::class);

beforeEach(function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
    ]);

    Route::middleware('auth:bfc')->get('/bfc-guarded', fn (): array => [
        'ok' => true,
        'principal' => auth('bfc')->id(),
    ]);
});

it('leaks nothing when a bearer credential authenticates', function (): void {
    $minted = $this->mintCredential();

    $response = $this->assertNoSecretLeakage($minted->plaintext(), function () use ($minted): TestResponse {
        return $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()]);
    });

    $response->assertOk()->assertJsonPath('ok', true);

    $this->assertResponseCarriesNoSecret($response, $minted->plaintext());
});

it('leaks nothing when a basic credential authenticates', function (): void {
    $minted = $this->mintCredential(['kind' => CredentialKind::Basic]);

    $response = $this->assertNoSecretLeakage($minted->plaintext(), function () use ($minted): TestResponse {
        return $this->getJson('/bfc-guarded', ['Authorization' => $minted->basicHeader()]);
    });

    $response->assertOk()->assertJsonPath('ok', true);

    $this->assertResponseCarriesNoSecret($response, $minted->plaintext());
});

it('leaks nothing when a presented secret is rejected', function (): void {
    $minted = $this->mintCredential(['revoked_at' => now()]);

    $response = $this->assertNoSecretLeakage($minted->plaintext(), function () use ($minted): TestResponse {
        return $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()]);
    });

    $response->assertUnauthorized();

    $this->assertResponseCarriesNoSecret($response, $minted->plaintext());
});
