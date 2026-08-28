<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConfigMapHolderDeclaration;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Symfony\Component\Mailer\SentMessage;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

function onDemandRecipients(): array
{
    $recipients = [];

    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        function (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable) use (&$recipients): bool {
            $recipients[] = [$notification->event, $notifiable->routes['mail'] ?? null];

            return true;
        },
    );

    return $recipients;
}

it('notifies the issuer on exchange with the exchange actor recorded', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');

    $claimCode = auditIssueCode('person@example.test');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        fn (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => $notification->event === 'exchanged'
            && ($notifiable->routes['mail'] ?? null) === 'issuer@example.test',
    );

    // The notice is useful because the actor is on the audit row (SEC-6).
    $exchanged = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Exchanged->value)
        ->firstOrFail();

    expect($exchanged->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($exchanged->actor_ref)->not->toBeNull();
});

it('notifies the intended recipient on first use of a credential from an addressed code', function (): void {
    Notification::fake();

    $claimCode = auditIssueCode('person@example.test');
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $durable = (string) $exchange->json('durable_token');

    app(TokenRegistry::class)->resolve($durable);

    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        fn (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => $notification->event === 'first_used'
            && ($notifiable->routes['mail'] ?? null) === 'person@example.test',
    );
});

it('notifies nobody for an unaddressed code under the default declaration, with no issuer fallback', function (): void {
    Notification::fake();
    // The issuer inbox IS configured: proving first_used does not fall back
    // to it requires it to exist.
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');

    $claimCode = auditIssueCode(null);
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $durable = (string) $exchange->json('durable_token');

    app(TokenRegistry::class)->resolve($durable);

    // Exactly ONE notification went anywhere: the issuer's exchange notice.
    // The unaddressed first_used resolved to NOBODY — not to the issuer,
    // not to any operator.
    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);

    foreach (onDemandRecipients() as [$event, $email]) {
        expect($event)->toBe('exchanged')
            ->and($email)->toBe('issuer@example.test');
    }
});

it('resolves the holder to the bound user email through the app declaration', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $claimCode = auditIssueCode(null);
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $durable = (string) $exchange->json('durable_token');

    $durableId = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail()
        ->durable_token_id;

    // This credential is bound to a user; the declaration knows their email.
    config()->set('built-for-cloud-tests.holder_map', [$durableId => 'bound-user@example.test']);

    app(TokenRegistry::class)->resolve($durable);

    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        fn (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => $notification->event === 'first_used'
            && ($notifiable->routes['mail'] ?? null) === 'bound-user@example.test',
    );
});

it('extends per app: a policy row added in config notifies, a removed row stays silent', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');
    // The app declares its own table: revocations notify the issuer, and
    // nothing else notifies anyone.
    config()->set('built-for-cloud.notifications.policy', ['revoked' => ['issuer']]);

    $registry = app(TokenRegistry::class);
    $registry->store('policy-target', hash('sha256', 'policy-secret'));
    $registry->revoke('policy-target');

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);

    // With the exchanged row removed, an exchange notifies no one.
    $claimCode = auditIssueCode('person@example.test');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
});

it('carries ids and metadata only in notification payloads and mail bodies', function (): void {
    // Real sends into the array transport — no notification fake — so the
    // asserted artifact is the rendered mail itself.
    config()->set('mail.default', 'array');
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $this->beginLeakWatch('marker-not-yet-known');

    $claimCode = auditIssueCode('person@example.test');
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();
    $durable = (string) $exchange->json('durable_token');

    $durableId = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail()
        ->durable_token_id;

    config()->set('built-for-cloud-tests.holder_map', [$durableId => 'bound-user@example.test']);

    // First use, rotation, revocation — every hooked surface fires.
    app(TokenRegistry::class)->resolve($durable);
    app(TokenRegistry::class)->rotate('person@example.test', hash('sha256', 'rotated-replacement'));
    app(TokenRegistry::class)->revoke('person@example.test');

    // The claim code escaped into no side-effect channel — audit rows and
    // outbox rows included (the at-rest sweep covers both tables).
    $this->leakWatchMarker = $claimCode;
    $this->assertNoLeaks();

    /** @var list<SentMessage> $messages */
    $messages = app('mail.manager')->mailer('array')->getSymfonyTransport()->messages()->all();

    expect(count($messages))->toBeGreaterThanOrEqual(2);

    foreach ($messages as $sent) {
        $rendered = $sent->getOriginalMessage()->toString();

        expect($rendered)->not->toContain($claimCode)
            ->and($rendered)->not->toContain($durable)
            ->and($rendered)->not->toContain(hash('sha256', $claimCode))
            ->and($rendered)->not->toContain(hash('sha256', $durable));
    }

    // And the audit rows themselves: ids only — no plaintext, no hash — for
    // every hooked surface.
    $events = CredentialAuditEvent::query()->get();

    expect($events->pluck('event')->map(fn (LifecycleEventType $event): string => $event->value)->unique()->values()->all())
        ->toContain('issued', 'exchanged', 'first_used', 'rotated', 'revoked');

    foreach ($events as $event) {
        foreach ($event->getAttributes() as $column => $value) {
            if (! is_string($value)) {
                continue;
            }

            expect(str_contains($value, $claimCode))->toBeFalse("audit column {$column} carried the claim code")
                ->and(str_contains($value, $durable))->toBeFalse("audit column {$column} carried the durable secret")
                ->and($value === hash('sha256', $claimCode))->toBeFalse("audit column {$column} carried the code hash")
                ->and($value === hash('sha256', $durable))->toBeFalse("audit column {$column} carried the durable hash");
        }
    }
});
