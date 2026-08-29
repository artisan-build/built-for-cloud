<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('creates ownership schemas and resolves pending claims by plaintext token', function (): void {
    $plainTextToken = 'claim-secret';
    $claim = OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($plainTextToken),
    ]);

    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken('consumed-secret'),
        'consumed_at' => now(),
    ]);

    expect(Schema::hasTable('ownership_claims'))->toBeTrue()
        ->and(Schema::hasColumns('ownership_claims', ['id', 'token_hash', 'consumed_at']))->toBeTrue()
        ->and(Schema::hasTable('ownership'))->toBeTrue()
        ->and(Schema::hasColumns('ownership', ['id', 'owner_token_id', 'notify_callback', 'webhook_secret', 'pending_claim_id']))->toBeTrue()
        ->and(OwnershipClaim::query()->pending()->count())->toBe(1)
        ->and(OwnershipClaim::resolve($plainTextToken)?->is($claim))->toBeTrue()
        ->and(OwnershipClaim::resolve('consumed-secret'))->toBeNull();
});

it('returns unauthenticated bfc meta for unclaimed and claimed environments', function (): void {
    config(['built-for-cloud.product' => 'Sink']);

    $this->getJson('/bfc/meta')
        ->assertOk()
        ->assertExactJson([
            'product' => 'Sink',
            'bfc_version' => BuiltForCloud::VERSION,
            'api_version' => BuiltForCloud::API_VERSION,
            'capabilities' => ['tokens', 'ownership', 'onboarding', 'webhooks', 'credentials', 'console-keys', 'console-vitals'],
            'claimed' => false,
        ]);

    $token = ApiToken::factory()->create();

    Ownership::query()->create([
        'owner_token_id' => $token->getKey(),
    ]);

    $this->getJson('/bfc/meta')
        ->assertOk()
        ->assertJsonPath('claimed', true);
});

it('rate limits the bfc meta route', function (): void {
    $route = Route::getRoutes()->match(request()->create('/bfc/meta', 'GET'));

    expect($route->gatherMiddleware())->toContain('throttle:bfc-public');
});
