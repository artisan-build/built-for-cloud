<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['built-for-cloud.product' => 'Sink']);
    Queue::fake();

    Route::middleware('bfc.token.admin')->post('/owner-gate', fn (): array => ['ok' => true]);
});

it('claims an unowned environment with a claim token and returns an admin owner token once', function (): void {
    $claimToken = createOwnershipClaim('initial-claim');

    $response = $this->postJson('/bfc/ownership/claim', [
        'token' => $claimToken,
        'notify_callback' => 'https://console.example.test/hook',
    ]);

    $response->assertCreated()
        ->assertJsonPath('product', 'Sink')
        ->assertJsonStructure(['owner_token', 'webhook_secret', 'product']);

    $ownerPlaintext = (string) $response->json('owner_token');
    $webhookSecret = (string) $response->json('webhook_secret');
    $ownership = Ownership::current();

    expect($ownership)->not->toBeNull()
        ->and($ownership?->notify_callback)->toBe('https://console.example.test/hook')
        ->and($ownership?->webhook_secret)->toBe($webhookSecret)
        ->and($ownership?->pending_claim_id)->toBeNull()
        ->and(OwnershipClaim::resolve($claimToken))->toBeNull();

    $ownerToken = ApiToken::query()->whereKey($ownership?->owner_token_id)->firstOrFail();

    expect($ownerToken->abilities)->toBe([Scope::Admin->value]);

    $this->postJson('/owner-gate', [], ownerHeaders($ownerPlaintext))->assertOk();
    $this->postJson('/bfc/ownership/claim', ['token' => $claimToken])->assertUnauthorized();
});

it('releases ownership for make before break and keeps the old owner valid until cutover', function (): void {
    $ownerPlaintext = claimInitialOwner();

    $release = $this->postJson('/bfc/ownership/release', [
        'notify_callback' => 'https://new-owner.example.test/hook',
    ], ownerHeaders($ownerPlaintext));

    $release->assertCreated()->assertJsonStructure(['swap_token']);

    $swapToken = (string) $release->json('swap_token');
    $ownership = Ownership::current();

    expect($ownership?->pending_claim_id)->not->toBeNull()
        ->and(OwnershipClaim::resolve($swapToken)?->getKey())->toBe($ownership?->pending_claim_id)
        ->and($ownership?->notify_callback)->toBe('https://new-owner.example.test/hook');

    $this->postJson('/owner-gate', [], ownerHeaders($ownerPlaintext))->assertOk();
});

it('cuts over ownership with the pending claim and revokes the old owner token', function (): void {
    $ownerPlaintext = claimInitialOwner();
    $oldOwnership = Ownership::current();
    $oldOwnerTokenId = $oldOwnership?->owner_token_id;
    $oldWebhookSecret = $oldOwnership?->webhook_secret;
    $swapToken = releaseOwnership($ownerPlaintext);

    $cutover = $this->postJson('/bfc/ownership/claim', [
        'token' => $swapToken,
        'notify_callback' => 'https://cutover.example.test/hook',
    ]);

    $cutover->assertCreated()->assertJsonStructure(['owner_token', 'webhook_secret', 'product']);

    $newOwnerPlaintext = (string) $cutover->json('owner_token');
    $ownership = Ownership::current();

    expect($ownership?->owner_token_id)->not->toBe($oldOwnerTokenId)
        ->and($ownership?->pending_claim_id)->toBeNull()
        ->and($ownership?->notify_callback)->toBe('https://cutover.example.test/hook')
        ->and($ownership?->webhook_secret)->not->toBe($oldWebhookSecret)
        ->and(OwnershipClaim::resolve($swapToken))->toBeNull();

    $oldOwnerToken = ApiToken::query()->whereKey($oldOwnerTokenId)->firstOrFail();

    expect($oldOwnerToken->expires_at)->not->toBeNull()
        ->and($oldOwnerToken->revoked_at)->not->toBeNull();

    $this->postJson('/owner-gate', [], ownerHeaders($ownerPlaintext))->assertUnauthorized();
    $this->postJson('/owner-gate', [], ownerHeaders($newOwnerPlaintext))->assertOk();
});

it('cancels a pending transfer and invalidates the outstanding swap token', function (): void {
    $ownerPlaintext = claimInitialOwner();
    $swapToken = releaseOwnership($ownerPlaintext);

    $this->postJson('/bfc/ownership/cancel-transfer', [], ownerHeaders($ownerPlaintext))
        ->assertOk()
        ->assertJsonPath('ok', true);

    expect(Ownership::current()?->pending_claim_id)->toBeNull()
        ->and(OwnershipClaim::resolve($swapToken))->toBeNull();

    $this->postJson('/bfc/ownership/claim', ['token' => $swapToken])->assertUnauthorized();
});

it('supersedes an older release swap token when releasing twice', function (): void {
    $ownerPlaintext = claimInitialOwner();
    $firstSwapToken = releaseOwnership($ownerPlaintext);
    $secondSwapToken = releaseOwnership($ownerPlaintext);

    expect(OwnershipClaim::resolve($firstSwapToken))->toBeNull()
        ->and(OwnershipClaim::resolve($secondSwapToken))->not->toBeNull();

    $this->postJson('/bfc/ownership/claim', ['token' => $firstSwapToken])->assertUnauthorized();
    $this->postJson('/bfc/ownership/claim', ['token' => $secondSwapToken])->assertCreated();
});

it('rejects a non pending claim token once an environment is already claimed', function (): void {
    claimInitialOwner();
    $hostileClaim = createOwnershipClaim('hostile-claim');

    $this->postJson('/bfc/ownership/claim', ['token' => $hostileClaim])
        ->assertStatus(409)
        ->assertJsonPath('message', 'already claimed');

    expect(OwnershipClaim::resolve($hostileClaim))->not->toBeNull();
});

function createOwnershipClaim(string $plainTextToken): string
{
    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($plainTextToken),
    ]);

    return $plainTextToken;
}

function claimInitialOwner(string $claimToken = 'initial-claim'): string
{
    createOwnershipClaim($claimToken);

    $response = test()->postJson('/bfc/ownership/claim', ['token' => $claimToken]);
    $response->assertCreated();

    return (string) $response->json('owner_token');
}

function releaseOwnership(string $ownerPlaintext): string
{
    $response = test()->postJson('/bfc/ownership/release', [], ownerHeaders($ownerPlaintext));
    $response->assertCreated();

    return (string) $response->json('swap_token');
}

/**
 * @return array{Authorization: string}
 */
function ownerHeaders(string $plainTextToken): array
{
    return ['Authorization' => 'Bearer '.$plainTextToken];
}
