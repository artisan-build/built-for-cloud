<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;

/**
 * A headless BfC app has no auth guard at all: its `config/auth.php` ships with
 * `defaults.guard => null` and `guards => []`. Laravel's ThrottleRequests builds
 * its request signature by calling `$request->user()`, which makes the
 * AuthManager throw — turning every throttled BfC public route into a 500.
 *
 * These routes are public/pre-auth, so they must throttle by IP and never
 * resolve a user.
 */
uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'auth.defaults.guard' => null,
        'auth.guards' => [],
    ]);
});

it('serves the meta route on a headless app with no auth guard', function (): void {
    $this->getJson('/bfc/meta')->assertOk();
});

it('serves the ownership claim route on a headless app with no auth guard', function (): void {
    $this->postJson('/bfc/ownership/claim', [])->assertStatus(422);

    $this->postJson('/bfc/ownership/claim', ['token' => 'not-a-real-claim'])->assertUnauthorized();
});

it('serves the onboarding routes on a headless app with no auth guard', function (): void {
    $this->postJson('/bfc/onboarding/exchange', ['token' => 'not-a-real-token'])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_code');

    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer not-a-real-token'])
        ->assertNotFound()
        ->assertJsonPath('error', 'code_not_found');
});

it('claims ownership normally on a headless app with no auth guard', function (): void {
    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken('headless-claim'),
    ]);

    $this->postJson('/bfc/ownership/claim', ['token' => 'headless-claim'])
        ->assertCreated()
        ->assertJsonStructure(['owner_token']);

    expect(Ownership::query()->whereNotNull('owner_token_id')->exists())->toBeTrue()
        ->and(ApiToken::query()->where('name', 'owner')->exists())->toBeTrue();
});

it('throttles the meta route at sixty per minute by ip', function (): void {
    foreach (range(1, 60) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
            ->getJson('/bfc/meta')
            ->assertOk();
    }

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
        ->getJson('/bfc/meta')
        ->assertStatus(429);

    // A different IP gets its own bucket, which proves the key is the IP.
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->getJson('/bfc/meta')
        ->assertOk();
});

it('throttles the ownership claim route at ten per minute by ip', function (): void {
    foreach (range(1, 10) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.3'])
            ->postJson('/bfc/ownership/claim', ['token' => 'not-a-real-claim'])
            ->assertUnauthorized();
    }

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.3'])
        ->postJson('/bfc/ownership/claim', ['token' => 'not-a-real-claim'])
        ->assertStatus(429);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.4'])
        ->postJson('/bfc/ownership/claim', ['token' => 'not-a-real-claim'])
        ->assertUnauthorized();
});

it('registers no bfc route that throttles on anything but a named bfc limiter', function (): void {
    $unnamed = collect(Route::getRoutes()->getRoutes())
        ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/'))
        ->flatMap(fn (RoutingRoute $route): array => $route->gatherMiddleware())
        ->filter(fn (mixed $middleware): bool => is_string($middleware) && str_starts_with($middleware, 'throttle:'))
        ->reject(fn (string $middleware): bool => str_starts_with($middleware, 'throttle:bfc-'))
        ->values()
        ->all();

    expect($unnamed)->toBe([]);
});
