<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\OutboxDrainer;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConfigMapHolderDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ThrowingHolderDeclaration;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use RuntimeException;

uses(RefreshDatabase::class);

function revokeWithHolderPolicy(string $declaration): CredentialOutboxEntry
{
    config()->set('built-for-cloud.notifications.policy', ['revoked' => ['holder']]);
    config()->set('built-for-cloud.credentials.declaration', $declaration);

    $registry = app(TokenRegistry::class);
    $token = $registry->store('outbox-target', hash('sha256', 'outbox-secret-'.Str::random(8)));

    config()->set('built-for-cloud-tests.holder_map', [$token->id => 'holder@example.test']);

    $registry->revoke('outbox-target');

    $auditEvent = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('credential_id', $token->id)
        ->firstOrFail();

    return CredentialOutboxEntry::query()
        ->where('audit_event_id', $auditEvent->id)
        ->firstOrFail();
}

it('keeps the row claimable when a subscriber throws, and a later drain delivers it', function (): void {
    Notification::fake();

    // The revoke commits; the post-commit dispatcher runs into a throwing
    // subscriber. The failure must not escape the caller.
    $entry = revokeWithHolderPolicy(ThrowingHolderDeclaration::class);

    $entry->refresh();
    expect($entry->delivered_at)->toBeNull()
        ->and($entry->claimed_at)->toBeNull()
        ->and($entry->attempts)->toBe(1)
        ->and($entry->last_error)->toBe(RuntimeException::class);

    Notification::assertNothingSent();

    // The subscriber recovers; the drain command delivers the same row.
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $this->artisan('bfc:outbox:drain')
        ->expectsOutputToContain('Delivered 1 pending outbox row(s).')
        ->assertSuccessful();

    $entry->refresh();
    expect($entry->delivered_at)->not->toBeNull()
        ->and($entry->attempts)->toBe(2);

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
});

it('delivers exactly one notification when the same row is drained twice', function (): void {
    Notification::fake();

    $entry = revokeWithHolderPolicy(ConfigMapHolderDeclaration::class);

    // The post-commit dispatcher already delivered it once.
    $entry->refresh();
    expect($entry->delivered_at)->not->toBeNull();

    // Draining again — the command and the service both — sends nothing more.
    expect(app(OutboxDrainer::class)->drain())->toBe(0);
    $this->artisan('bfc:outbox:drain')
        ->expectsOutputToContain('Delivered 0 pending outbox row(s).')
        ->assertSuccessful();

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
});

it('honours a live claim and takes over a stale one', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.policy', []);

    $auditEvent = CredentialAuditEvent::query()->create([
        'id' => (string) Str::uuid(),
        'event' => LifecycleEventType::Revoked,
        'credential_id' => (string) Str::uuid(),
        'occurred_at' => now(),
    ]);

    $entry = CredentialOutboxEntry::query()->create([
        'id' => (string) Str::uuid(),
        'audit_event_id' => $auditEvent->id,
        'dedup_key' => $auditEvent->id,
        'claimed_at' => now()->subSeconds(30),
        'attempts' => 1,
    ]);

    // A live claim (30s old, TTL 300): another consumer is presumed alive
    // mid-delivery, and the drain must not double-deliver under it.
    expect(app(OutboxDrainer::class)->drain())->toBe(0);

    // The claim goes stale past the TTL: the consumer died mid-delivery,
    // and the row becomes claimable again.
    CredentialOutboxEntry::query()->whereKey($entry->id)
        ->update(['claimed_at' => now()->subSeconds(301)]);

    expect(app(OutboxDrainer::class)->drain())->toBe(1)
        ->and($entry->refresh()->delivered_at)->not->toBeNull();
});

it('enforces the delivery dedup key at insert', function (): void {
    $auditEvent = CredentialAuditEvent::query()->create([
        'id' => (string) Str::uuid(),
        'event' => LifecycleEventType::Expiring,
        'credential_id' => (string) Str::uuid(),
        'occurred_at' => now(),
    ]);

    CredentialOutboxEntry::query()->create([
        'id' => (string) Str::uuid(),
        'audit_event_id' => $auditEvent->id,
        'dedup_key' => 'expiring:some-credential:12345',
    ]);

    // The same logical event cannot be enqueued twice, whatever row tries.
    expect(fn (): CredentialOutboxEntry => CredentialOutboxEntry::query()->create([
        'id' => (string) Str::uuid(),
        'audit_event_id' => $auditEvent->id,
        'dedup_key' => 'expiring:some-credential:12345',
    ]))->toThrow(UniqueConstraintViolationException::class);
});
