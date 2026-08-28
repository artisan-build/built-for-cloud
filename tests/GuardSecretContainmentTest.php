<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\LogsAuthorizationHeaderMiddleware;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\AssertionFailedError;

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

it('would catch a middleware that logs the authorization header on the basic path', function (): void {
    // The falsifiability proof for this surface: a deliberately-planted
    // leaky middleware logs the incoming Authorization header — for a
    // basic credential that is `Basic base64(user:secret)`, which only
    // base64-aware detection can see. The real guard route carries no such
    // plant; this proves the channel would have fired if it did.
    Route::middleware([LogsAuthorizationHeaderMiddleware::class, 'auth:bfc'])
        ->get('/bfc-guarded-leaky', fn (): array => ['ok' => true]);

    $minted = $this->mintCredential(['kind' => CredentialKind::Basic]);

    $failure = null;

    try {
        $this->assertNoSecretLeakage($minted->plaintext(), function () use ($minted): TestResponse {
            return $this->getJson('/bfc-guarded-leaky', ['Authorization' => $minted->basicHeader()]);
        });
    } catch (AssertionFailedError $failure) {
    }

    expect($failure)->toBeInstanceOf(AssertionFailedError::class)
        ->and($failure->getMessage())->toContain('[log]')
        ->and($failure->getMessage())->toContain('base64-decoded')
        ->and($failure->getMessage())->not->toContain($minted->plaintext());
});
