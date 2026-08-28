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
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Mail\Events\MessageSending;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use RuntimeException;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

uses(RefreshDatabase::class);

/**
 * Every To address the array transport has accepted so far, in send order.
 *
 * @return list<string>
 */
function sentMailAddresses(): array
{
    $addresses = [];

    /** @var SentMessage $sent */
    foreach (app('mail.manager')->mailer('array')->getSymfonyTransport()->messages() as $sent) {
        $original = $sent->getOriginalMessage();

        if ($original instanceof Email) {
            foreach ($original->getTo() as $address) {
                $addresses[] = $address->getAddress();
            }
        }
    }

    return $addresses;
}

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

    // A live claim (30s old, TTL 600): another consumer is presumed alive
    // mid-delivery, and the drain must not double-deliver under it.
    expect(app(OutboxDrainer::class)->drain())->toBe(0);

    // The claim goes stale past the TTL: the consumer died mid-delivery,
    // and the row becomes claimable again.
    CredentialOutboxEntry::query()->whereKey($entry->id)
        ->update(['claimed_at' => now()->subSeconds(601)]);

    expect(app(OutboxDrainer::class)->drain())->toBe(1)
        ->and($entry->refresh()->delivered_at)->not->toBeNull();
});

it('redelivers only to the recipients not yet marked after a partial failure', function (): void {
    // Real sends into the array transport so the sabotage can hit ONE
    // recipient's transport send while the other's lands.
    config()->set('mail.default', 'array');
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');
    config()->set('built-for-cloud.notifications.policy', ['revoked' => ['issuer', 'holder']]);
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $registry = app(TokenRegistry::class);
    $token = $registry->store('partial-target', hash('sha256', 'partial-secret'));

    config()->set('built-for-cloud-tests.holder_map', [$token->id => 'holder@example.test']);

    // The holder's send fails; the issuer's (sent first, policy order)
    // succeeds.
    $sabotage = true;

    Event::listen(MessageSending::class, function (MessageSending $event) use (&$sabotage): void {
        $to = array_map(
            static fn (Address $address): string => $address->getAddress(),
            $event->message->getTo(),
        );

        if ($sabotage && in_array('holder@example.test', $to, true)) {
            throw new RuntimeException('simulated mail transport failure');
        }
    });

    $registry->revoke('partial-target');

    $entry = CredentialOutboxEntry::query()->latest('created_at')->latest('id')->firstOrFail();

    // The issuer's delivery is MARKED and survives; the row is released
    // for retry with the failure recorded.
    expect($entry->delivered_at)->toBeNull()
        ->and($entry->claimed_at)->toBeNull()
        ->and($entry->attempts)->toBe(1)
        ->and($entry->last_error)->toBe(RuntimeException::class)
        ->and(array_keys($entry->delivered_recipients ?? []))->toBe(['issuer@example.test']);

    expect(sentMailAddresses())->toBe(['issuer@example.test']);

    // The transport recovers: redelivery reaches ONLY the holder — the
    // issuer is not sent to twice.
    $sabotage = false;

    $this->artisan('bfc:outbox:drain')
        ->expectsOutputToContain('Delivered 1 pending outbox row(s).')
        ->assertSuccessful();

    $entry->refresh();
    expect($entry->delivered_at)->not->toBeNull()
        ->and(array_keys($entry->delivered_recipients ?? []))->toBe(['issuer@example.test', 'holder@example.test']);

    expect(sentMailAddresses())->toBe(['issuer@example.test', 'holder@example.test']);

    // With every recipient marked, further drains send nothing new.
    expect(app(OutboxDrainer::class)->drain())->toBe(0)
        ->and(sentMailAddresses())->toBe(['issuer@example.test', 'holder@example.test']);
});

it('never fails the committed request when the post-commit drain breaks', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');

    $claimCode = auditIssueCode('postcommit@example.test');

    // Break the post-commit drain at its FIRST touch of the outbox (the
    // pending select), the way a dropped connection would: nothing gets
    // claimed, and the failure happens strictly AFTER the exchange
    // committed.
    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credential_outbox')) {
            $armed = false;

            throw new RuntimeException('simulated infrastructure failure during the post-commit drain');
        }
    });

    // The response is still the success the committed mutation earned — no
    // server_error inviting the client to re-claim a code that burned.
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    expect($armed)->toBeFalse();

    // The exchanged event's row sits undelivered and UNCLAIMED…
    $exchanged = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Exchanged->value)
        ->firstOrFail();

    $entry = CredentialOutboxEntry::query()->where('audit_event_id', $exchanged->id)->firstOrFail();
    expect($entry->delivered_at)->toBeNull()
        ->and($entry->claimed_at)->toBeNull();

    Notification::assertNothingSent();

    // …and a later manual drain delivers it.
    $this->artisan('bfc:outbox:drain')->assertSuccessful();

    expect($entry->refresh()->delivered_at)->not->toBeNull();
    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
});

it('makes every stale-owner write a no-op once a newer owner holds the row', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.policy', ['revoked' => ['holder']]);
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $credentialId = (string) Str::uuid();
    config()->set('built-for-cloud-tests.holder_map', [$credentialId => 'holder@example.test']);

    $auditEvent = CredentialAuditEvent::query()->create([
        'id' => (string) Str::uuid(),
        'event' => LifecycleEventType::Revoked,
        'credential_id' => $credentialId,
        'occurred_at' => now(),
    ]);

    // A drain (owner T1) stalled long enough for its claim to expire.
    $entry = CredentialOutboxEntry::query()->create([
        'id' => (string) Str::uuid(),
        'audit_event_id' => $auditEvent->id,
        'dedup_key' => $auditEvent->id,
        'claimed_at' => now()->subSeconds(601),
        'claim_token' => 'stale-owner-token',
        'attempts' => 1,
    ]);

    // A new owner re-claims (fresh token), delivers, marks, completes.
    expect(app(OutboxDrainer::class)->drain())->toBe(1);

    $entry->refresh();
    expect($entry->claim_token)->not->toBeNull()
        ->and($entry->claim_token)->not->toBe('stale-owner-token')
        ->and($entry->delivered_at)->not->toBeNull()
        ->and(array_keys($entry->delivered_recipients ?? []))->toBe(['holder@example.test']);

    $newOwnerState = $entry->getAttributes();

    // The stale owner wakes up and issues its three write shapes, each
    // fenced on the token it still holds: marker update, release,
    // completion. Every one is a no-op.
    $staleMarkerWrite = CredentialOutboxEntry::query()
        ->whereKey($entry->id)
        ->where('claim_token', 'stale-owner-token')
        ->update(['delivered_recipients' => json_encode(['clobbered@example.test' => now()->toIso8601String()])]);

    $staleRelease = CredentialOutboxEntry::query()
        ->whereKey($entry->id)
        ->where('claim_token', 'stale-owner-token')
        ->update(['claimed_at' => null, 'claim_token' => null, 'last_error' => RuntimeException::class]);

    $staleCompletion = CredentialOutboxEntry::query()
        ->whereKey($entry->id)
        ->where('claim_token', 'stale-owner-token')
        ->whereNull('delivered_at')
        ->update(['delivered_at' => now()]);

    expect($staleMarkerWrite)->toBe(0)
        ->and($staleRelease)->toBe(0)
        ->and($staleCompletion)->toBe(0)
        // The row is byte-for-byte the new owner's state.
        ->and($entry->refresh()->getAttributes())->toBe($newOwnerState);

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
});

it('stops a stale owner mid-loop after a takeover, sending no further recipients', function (): void {
    config()->set('mail.default', 'array');
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');
    config()->set('built-for-cloud.notifications.policy', ['revoked' => ['issuer', 'holder']]);
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $registry = app(TokenRegistry::class);
    $token = $registry->store('fence-target', hash('sha256', 'fence-secret'));

    config()->set('built-for-cloud-tests.holder_map', [$token->id => 'holder@example.test']);

    // During owner A's FIRST send (the issuer's), a takeover happens: A's
    // claim is presumed expired and owner B re-claims the row and delivers
    // everything. A's marker write for the issuer must then hit zero rows
    // and A must stop — the holder is never sent by A.
    $armed = true;

    Event::listen(MessageSending::class, function () use (&$armed): void {
        if (! $armed) {
            return;
        }

        $armed = false;

        DB::table('credential_outbox')->update([
            'claim_token' => 'takeover-token',
            'claimed_at' => now(),
            'delivered_recipients' => json_encode([
                'issuer@example.test' => now()->toIso8601String(),
                'holder@example.test' => now()->toIso8601String(),
            ]),
        ]);
    });

    $registry->revoke('fence-target');

    // A's issuer send had already left; nothing further followed it.
    expect($armed)->toBeFalse()
        ->and(sentMailAddresses())->toBe(['issuer@example.test']);

    // The row is B's, untouched by A: B's markers, B's claim, no
    // completion stamped by a non-owner.
    $entry = CredentialOutboxEntry::query()->latest('created_at')->latest('id')->firstOrFail();
    expect($entry->claim_token)->toBe('takeover-token')
        ->and(array_keys($entry->delivered_recipients ?? []))->toBe(['issuer@example.test', 'holder@example.test'])
        ->and($entry->delivered_at)->toBeNull();

    // And no later drain re-sends under B's live claim.
    expect(app(OutboxDrainer::class)->drain())->toBe(0)
        ->and(sentMailAddresses())->toBe(['issuer@example.test']);
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
