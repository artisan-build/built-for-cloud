<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Jobs\DeliverOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['built-for-cloud.product' => 'Sink']);
});

it('queues a signed release pending webhook with the current callback and secret', function (): void {
    $ownerPlaintext = webhookClaimInitialOwnerWithCallback('https://owner.example.test/webhook');
    $ownership = Ownership::current();
    $secret = (string) $ownership?->webhook_secret;

    Queue::fake();

    $this->postJson('/bfc/ownership/release', [], webhookOwnerHeaders($ownerPlaintext))->assertCreated();

    Queue::assertPushed(DeliverOwnershipWebhook::class, function (DeliverOwnershipWebhook $job) use ($secret): bool {
        expect($job->callbackUrl)->toBe('https://owner.example.test/webhook')
            ->and($job->secret)->toBe($secret)
            ->and($job->event)->toBe('ownership.release_pending')
            ->and($job->payload)->toBe(['product' => 'Sink']);

        assertWebhookRequestIsSigned($job, $secret, 'https://owner.example.test/webhook');

        return true;
    });
});

it('queues transferred webhook to the departing owner with the old secret and callback', function (): void {
    $ownerPlaintext = webhookClaimInitialOwnerWithCallback('https://old-owner.example.test/webhook');
    $oldOwnership = Ownership::current();
    $oldSecret = (string) $oldOwnership?->webhook_secret;

    Queue::fake();

    $swapToken = webhookReleaseOwnership($ownerPlaintext);

    $this->postJson('/bfc/ownership/claim', [
        'token' => $swapToken,
        'notify_callback' => 'https://new-owner.example.test/webhook',
    ])->assertCreated();

    $newSecret = (string) Ownership::current()?->webhook_secret;

    expect($newSecret)->not->toBe($oldSecret);

    Queue::assertPushed(DeliverOwnershipWebhook::class, function (DeliverOwnershipWebhook $job) use ($oldSecret, $newSecret): bool {
        if ($job->event !== 'ownership.transferred') {
            return false;
        }

        expect($job->callbackUrl)->toBe('https://old-owner.example.test/webhook')
            ->and($job->secret)->toBe($oldSecret)
            ->and($job->secret)->not->toBe($newSecret)
            ->and($job->event)->toBe('ownership.transferred')
            ->and($job->payload)->toBe(['product' => 'Sink']);

        assertWebhookRequestIsSigned($job, $oldSecret, 'https://old-owner.example.test/webhook');

        return true;
    });
});

it('does not queue a webhook delivery when no callback is configured', function (): void {
    $ownerPlaintext = webhookClaimInitialOwner();

    Queue::fake();

    $this->postJson('/bfc/ownership/release', [], webhookOwnerHeaders($ownerPlaintext))->assertCreated();

    Queue::assertNothingPushed();
});

function webhookClaimInitialOwnerWithCallback(string $callbackUrl): string
{
    webhookCreateOwnershipClaim('initial-claim-with-callback');

    $response = test()->postJson('/bfc/ownership/claim', [
        'token' => 'initial-claim-with-callback',
        'notify_callback' => $callbackUrl,
    ]);
    $response->assertCreated();

    return (string) $response->json('owner_token');
}

function webhookClaimInitialOwner(): string
{
    webhookCreateOwnershipClaim('initial-claim');

    $response = test()->postJson('/bfc/ownership/claim', ['token' => 'initial-claim']);
    $response->assertCreated();

    return (string) $response->json('owner_token');
}

function webhookReleaseOwnership(string $ownerPlaintext): string
{
    $response = test()->postJson('/bfc/ownership/release', [], webhookOwnerHeaders($ownerPlaintext));
    $response->assertCreated();

    return (string) $response->json('swap_token');
}

function webhookCreateOwnershipClaim(string $plainTextToken): string
{
    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($plainTextToken),
    ]);

    return $plainTextToken;
}

/**
 * @return array{Authorization: string}
 */
function webhookOwnerHeaders(string $plainTextToken): array
{
    return ['Authorization' => 'Bearer '.$plainTextToken];
}

function assertWebhookRequestIsSigned(DeliverOwnershipWebhook $job, string $secret, string $callbackUrl): void
{
    Http::fake();

    $job->handle();

    Http::assertSent(function (Request $request) use ($secret, $callbackUrl): bool {
        $timestamp = (string) $request->header('X-BFC-Timestamp')[0];
        $signature = (string) $request->header('X-BFC-Signature')[0];
        $rawBody = $request->body();
        $expectedSignature = hash_hmac('sha256', $timestamp.'.'.$rawBody, $secret);

        expect($request->url())->toBe($callbackUrl)
            ->and($request->header('Content-Type')[0])->toContain('application/json')
            ->and($signature)->toBe($expectedSignature);

        return true;
    });
}
