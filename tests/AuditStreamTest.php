<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use RuntimeException;

uses(RefreshDatabase::class);

function auditEvents(LifecycleEventType $event): array
{
    return CredentialAuditEvent::query()
        ->where('event', $event->value)
        ->orderBy('occurred_at')
        ->orderBy('created_at')
        ->get()
        ->all();
}

it('audits issue with the code id, recipient, selected ttl, and operator actor', function (): void {
    $ownerToken = auditOperatorCredential('owner');

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'scope' => Scope::Consume->value,
        'ttl_seconds' => 3600,
    ], ['Authorization' => 'Bearer '.$ownerToken])->assertCreated();

    $events = auditEvents(LifecycleEventType::Issued);
    expect($events)->toHaveCount(1);

    $issued = $events[0];
    $code = OnboardingToken::query()->firstOrFail();
    $adminRow = Credential::query()->where('name', 'owner')->firstOrFail();

    expect($issued->code_id)->toBe($code->id)
        ->and($issued->credential_id)->toBeNull()
        ->and($issued->recipient)->toBe('person@example.test')
        ->and($issued->code_ttl_seconds)->toBe(3600)
        ->and($issued->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($issued->actor_ref)->toBe($adminRow->id)
        ->and($issued->environment)->toBe('testing');

    // The outbox row committed with it, keyed on the audit event.
    expect(CredentialOutboxEntry::query()->where('audit_event_id', $issued->id)->exists())->toBeTrue();
});

it('audits the supersession revocation when re-issuing over a pending exchanged code', function (): void {
    // First code exchanged but unused: its durable is pending make-before-break.
    $firstCode = auditIssueCode('super@example.test');
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $firstCode]);
    $exchange->assertCreated();

    $pendingDurableId = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($firstCode))
        ->firstOrFail()
        ->durable_credential_id;

    // Re-issuing for the same address+scope supersedes the pending code and
    // revokes its never-used durable — and audits that revocation.
    auditIssueCode('super@example.test');

    $revocations = auditEvents(LifecycleEventType::Revoked);
    $superseded = array_values(array_filter(
        $revocations,
        fn (CredentialAuditEvent $event): bool => $event->credential_id === $pendingDurableId,
    ));

    expect($superseded)->toHaveCount(1)
        ->and($superseded[0]->reason_code)->toBe(AuditReason::Superseded)
        ->and($superseded[0]->actor_type)->toBe(AuditActorType::OperatorIntegration);
});

it('audits exchange and links both revocations old-to-new with supersession lineage', function (): void {
    // A live durable of the same name+scope that exchange's sweep revokes.
    $liveDurable = Credential::factory()->create([
        'name' => 'lineage@example.test',
        'subject_ref' => 'lineage@example.test',
        'abilities' => [Scope::Consume->value],
    ]);

    $claimCode = auditIssueCode('lineage@example.test');

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();
    $newId = $code->durable_credential_id;

    $exchanged = auditEvents(LifecycleEventType::Exchanged);
    expect($exchanged)->toHaveCount(1)
        ->and($exchanged[0]->code_id)->toBe($code->id)
        ->and($exchanged[0]->credential_id)->toBe($newId)
        ->and($exchanged[0]->recipient)->toBe('lineage@example.test')
        // The exchange actor: the bearer of the code (SEC-6 wants it recorded).
        ->and($exchanged[0]->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($exchanged[0]->actor_ref)->toBe($code->id);

    // The sweep revocation carries old -> new lineage.
    $revoked = auditEvents(LifecycleEventType::Revoked);
    $sweep = array_values(array_filter(
        $revoked,
        fn (CredentialAuditEvent $event): bool => $event->credential_id === $liveDurable->id,
    ));

    expect($sweep)->toHaveCount(1)
        ->and($sweep[0]->reason_code)->toBe(AuditReason::Superseded)
        ->and($sweep[0]->superseded_by_credential_id)->toBe($newId);

    // A re-claim of the SAME code before first use revokes the pending
    // durable by its link, with lineage to the replacement.
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $replacementId = $code->refresh()->durable_credential_id;

    $linkRevocations = array_values(array_filter(
        auditEvents(LifecycleEventType::Revoked),
        fn (CredentialAuditEvent $event): bool => $event->credential_id === $newId,
    ));

    expect($linkRevocations)->toHaveCount(1)
        ->and($linkRevocations[0]->superseded_by_credential_id)->toBe($replacementId);
});

it('audits first use inside the burn transaction with the code linkage and recipient', function (): void {
    $claimCode = auditIssueCode('burn@example.test');
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $durable = (string) $exchange->json('durable_token');

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // The operator credential that issued has its own first_used row (its first
    // authenticated request IS a first use); scope to this durable.
    $durableFirstUses = fn (): array => array_values(array_filter(
        auditEvents(LifecycleEventType::FirstUsed),
        fn (CredentialAuditEvent $event): bool => $event->credential_id === $code->durable_credential_id,
    ));

    expect($durableFirstUses())->toHaveCount(0);

    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$durable])->assertOk();

    $firstUsed = $durableFirstUses();
    expect($firstUsed)->toHaveCount(1)
        ->and($firstUsed[0]->code_id)->toBe($code->id)
        ->and($firstUsed[0]->recipient)->toBe('burn@example.test')
        ->and($firstUsed[0]->actor_type)->toBe(AuditActorType::CredentialHolder);

    // A second use is not a first use: no further event.
    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$durable])->assertOk();
    expect($durableFirstUses())->toHaveCount(1);
});

it('audits rotation as issued replacement plus rotated originals with lineage', function (): void {
    $old = Credential::factory()->create(['name' => 'rotate-me']);

    $this->artisan('bfc:credential:rotate', ['id' => $old->id, '--local' => true])->assertSuccessful();
    $new = Credential::query()->where('id', '!=', $old->id)->sole();

    $issued = auditEvents(LifecycleEventType::Issued);
    expect($issued)->toHaveCount(1)
        ->and($issued[0]->credential_id)->toBe($new->id)
        ->and($issued[0]->reason_code)->toBe(AuditReason::Rotation);

    $rotated = auditEvents(LifecycleEventType::Rotated);
    expect($rotated)->toHaveCount(1)
        ->and($rotated[0]->credential_id)->toBe($old->id)
        ->and($rotated[0]->superseded_by_credential_id)->toBe($new->id)
        ->and($rotated[0]->reason_code)->toBe(AuditReason::Rotation);
});

it('audits emergency rotation with the emergency reason and the cli actor from the command', function (): void {
    $old = Credential::factory()->create(['name' => 'emergency-me']);

    $this->artisan('bfc:credential:rotate', [
        'id' => $old->id,
        '--local' => true,
        '--emergency' => true,
    ])->assertSuccessful();

    $rotated = auditEvents(LifecycleEventType::Rotated);
    expect($rotated)->toHaveCount(1)
        ->and($rotated[0]->credential_id)->toBe($old->id)
        ->and($rotated[0]->reason_code)->toBe(AuditReason::Emergency)
        ->and($rotated[0]->actor_type)->toBe(AuditActorType::CliOperator);
});

it('audits revocation with the operator-request reason and the cli actor', function (): void {
    $cliTarget = Credential::factory()->create(['name' => 'cli-revoked']);

    $this->artisan('bfc:credential:revoke', ['id' => $cliTarget->id, '--local' => true])
        ->assertSuccessful();

    $cliEvents = array_values(array_filter(
        auditEvents(LifecycleEventType::Revoked),
        fn (CredentialAuditEvent $event): bool => $event->credential_id === $cliTarget->id,
    ));

    expect($cliEvents)->toHaveCount(1)
        ->and($cliEvents[0]->reason_code)->toBe(AuditReason::OperatorRequest)
        ->and($cliEvents[0]->actor_type)->toBe(AuditActorType::CliOperator);
});

it('rolls the audit row and outbox row back with a failed exchange, delivering nothing', function (): void {
    Notification::fake();

    $claimCode = auditIssueCode('rollback@example.test');
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');

    $baselineAudit = CredentialAuditEvent::query()->count();
    $baselineOutbox = CredentialOutboxEntry::query()->count();

    // Kill the exchange transaction AFTER the audit insert: the outbox
    // insert follows it inside the same transaction, so throwing there
    // leaves an audit row already written when the rollback hits.
    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*insert\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credential_outbox')) {
            $armed = false;

            throw new RuntimeException('simulated failure after the audit insert');
        }
    });

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(500)
        ->assertJsonPath('error', 'server_error');

    expect($armed)->toBeFalse()
        // The mutation rolled back...
        ->and(OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($claimCode))->firstOrFail()->durable_credential_id)->toBeNull()
        // ...and took the audit and outbox rows with it.
        ->and(CredentialAuditEvent::query()->count())->toBe($baselineAudit)
        ->and(CredentialOutboxEntry::query()->count())->toBe($baselineOutbox);

    Notification::assertNothingSent();
});
