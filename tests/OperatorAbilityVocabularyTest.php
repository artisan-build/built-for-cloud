<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * GATE-3.7 — per-verb-family operator authority: least privilege by
 * default, one explicit break-glass name, rate-limited writes, audited
 * sensitive reads / denials / auth failures, and the stolen read-only
 * token named-negative against every mutation.
 */

/**
 * @param  list<string>|null  $abilities
 */
function operatorCredential(?array $abilities): MintedTestCredential
{
    return test()->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane-'.bin2hex(random_bytes(4)),
        'abilities' => $abilities,
    ]);
}

/**
 * Every mutation on the operator surface, as [method, uri, body] rows.
 * The target id is a live bearer credential so a passed gate would
 * actually bite.
 *
 * @return array<string, array{string, string, array<string, mixed>}>
 */
function operatorMutations(string $targetId): array
{
    return [
        'mint' => ['postJson', '/bfc/credentials', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme']],
        'rotate' => ['postJson', '/bfc/credentials/'.$targetId.'/rotate', []],
        'revoke' => ['deleteJson', '/bfc/credentials/'.$targetId, []],
        'activate' => ['postJson', '/bfc/credentials/'.$targetId.'/activate', ['delivery_fingerprint' => 'fp']],
        'invite' => ['postJson', '/bfc/invitations', ['email' => 'a@b.c', 'ttl_seconds' => 3600]],
        'offboard' => ['postJson', '/bfc/subjects/offboard', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme']],
    ];
}

it('locks the vocabulary names and the break-glass equivalence', function (): void {
    expect(OperatorAbility::CredentialRead->value)->toBe('credential:read')
        ->and(OperatorAbility::CredentialMint->value)->toBe('credential:mint')
        ->and(OperatorAbility::CredentialRotate->value)->toBe('credential:rotate')
        ->and(OperatorAbility::CredentialRevoke->value)->toBe('credential:revoke')
        ->and(OperatorAbility::SubjectOffboard->value)->toBe('subject:offboard')
        ->and(OperatorAbility::AuditRead->value)->toBe('audit:read')
        ->and(OperatorAbility::McpRead->value)->toBe('mcp:read')
        ->and(OperatorAbility::ADMIN)->toBe(EnsureCredentialAdmin::ABILITY)
        ->and(OperatorAbility::RESERVED_METADATA_READ)->toBe('metadata:read')
        ->and(OperatorAbility::adminEquivalent())->toBe([
            OperatorAbility::CredentialRead,
            OperatorAbility::CredentialMint,
            OperatorAbility::CredentialRotate,
            OperatorAbility::CredentialRevoke,
            OperatorAbility::SubjectOffboard,
            OperatorAbility::AuditRead,
        ]);

    // The reserved name stays reserved: no enum case enforces it.
    expect(OperatorAbility::tryFrom('metadata:read'))->toBeNull();
});

it('grants an operator credential nothing by default (least privilege)', function (): void {
    $bare = operatorCredential(null);
    $target = $this->mintCredential();

    $this->getJson('/bfc/credentials', ['Authorization' => $bare->bearerHeader()])->assertForbidden();

    foreach (operatorMutations($target->credential->id) as $name => [$method, $uri, $body]) {
        $this->{$method}($uri, $body, ['Authorization' => $bare->bearerHeader()])->assertForbidden();
    }
});

it('denies a stolen read-only operator token every mutation', function (): void {
    // The SEC-V3-06 named negative: `credential:read` (and `audit:read`)
    // must observe, never act.
    foreach ([OperatorAbility::CredentialRead, OperatorAbility::AuditRead] as $readAbility) {
        $stolen = operatorCredential([$readAbility->value]);
        $target = $this->mintCredential();

        foreach (operatorMutations($target->credential->id) as $name => [$method, $uri, $body]) {
            $this->{$method}($uri, $body, ['Authorization' => $stolen->bearerHeader()])
                ->assertForbidden();
        }

        // Nothing acted: the target still authenticates untouched.
        expect($target->credential->refresh()->revoked_at)->toBeNull()
            ->and($target->credential->rotated_at)->toBeNull();
    }

    // And the credential:read holder can still read — deny is per verb,
    // not per credential.
    $reader = operatorCredential([OperatorAbility::CredentialRead->value]);
    $this->getJson('/bfc/credentials', ['Authorization' => $reader->bearerHeader()])->assertOk();
});

it('scopes each verb family to its own ability', function (): void {
    $minter = operatorCredential([OperatorAbility::CredentialMint->value]);
    $revoker = operatorCredential([OperatorAbility::CredentialRevoke->value]);
    $rotator = operatorCredential([OperatorAbility::CredentialRotate->value]);

    // Mint may mint (and invite — same family) but not read, rotate, or revoke.
    $minted = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
    ], ['Authorization' => $minter->bearerHeader()])->assertCreated();

    $mintedId = (string) $minted->json('credential.id');

    $this->postJson('/bfc/invitations', ['email' => 'a@b.c', 'ttl_seconds' => 3600], ['Authorization' => $minter->bearerHeader()])
        ->assertCreated();
    $this->getJson('/bfc/credentials', ['Authorization' => $minter->bearerHeader()])->assertForbidden();
    $this->deleteJson('/bfc/credentials/'.$mintedId, [], ['Authorization' => $minter->bearerHeader()])->assertForbidden();
    $this->postJson('/bfc/credentials/'.$mintedId.'/rotate', [], ['Authorization' => $minter->bearerHeader()])->assertForbidden();

    // Rotate may rotate — and activate rides the same family (a 409 for a
    // non-hmac row proves the GATE passed and the action itself refused).
    $this->postJson('/bfc/credentials/'.$mintedId.'/rotate', [], ['Authorization' => $rotator->bearerHeader()])
        ->assertCreated();
    $this->postJson('/bfc/credentials/'.$mintedId.'/activate', ['delivery_fingerprint' => 'fp'], ['Authorization' => $rotator->bearerHeader()])
        ->assertStatus(409);
    $this->postJson('/bfc/credentials', ['subject_type' => 'external_consumer', 'subject_ref' => 'other'], ['Authorization' => $rotator->bearerHeader()])
        ->assertForbidden();

    // Revoke may revoke and nothing else.
    $this->deleteJson('/bfc/credentials/'.$mintedId, [], ['Authorization' => $revoker->bearerHeader()])->assertNoContent();
    $this->postJson('/bfc/credentials', ['subject_type' => 'external_consumer', 'subject_ref' => 'more'], ['Authorization' => $revoker->bearerHeader()])
        ->assertForbidden();
});

it('honors the explicit break-glass credential on every verb', function (): void {
    $breakGlass = operatorCredential([OperatorAbility::ADMIN]);

    $this->getJson('/bfc/credentials', ['Authorization' => $breakGlass->bearerHeader()])->assertOk();

    $minted = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
    ], ['Authorization' => $breakGlass->bearerHeader()])->assertCreated();

    $mintedId = (string) $minted->json('credential.id');

    $this->postJson('/bfc/credentials/'.$mintedId.'/rotate', [], ['Authorization' => $breakGlass->bearerHeader()])->assertCreated();
    $this->deleteJson('/bfc/credentials/'.$mintedId, [], ['Authorization' => $breakGlass->bearerHeader()])->assertNoContent();
});

it('audits the operator sensitive read with the acting principal, ids only', function (): void {
    $reader = operatorCredential([OperatorAbility::CredentialRead->value]);

    $this->getJson('/bfc/credentials', ['Authorization' => $reader->bearerHeader()])->assertOk();

    $reads = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::SensitiveRead->value)
        ->get();

    expect($reads)->toHaveCount(1)
        ->and($reads[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($reads[0]->actor_ref)->toBe($reader->credential->id)
        ->and((string) $reads[0]->note)->not->toContain($reader->plaintext());
});

it('audits a denied operator action with the acting principal', function (): void {
    $stolen = operatorCredential([OperatorAbility::CredentialRead->value]);

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
    ], ['Authorization' => $stolen->bearerHeader()])->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied[0]->actor_ref)->toBe($stolen->credential->id)
        ->and((string) $denied[0]->note)->toContain(OperatorAbility::CredentialMint->value)
        ->and((string) $denied[0]->note)->not->toContain($stolen->plaintext());
});

it('audits token-auth failures on the operator gate without echoing the presented secret', function (): void {
    $garbage = 'not-a-real-credential-'.bin2hex(random_bytes(16));

    $this->getJson('/bfc/credentials', ['Authorization' => 'Bearer '.$garbage])->assertUnauthorized();

    $failures = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get();

    expect($failures)->toHaveCount(1)
        ->and((string) $failures[0]->note)->toContain('token_auth_failure')
        ->and((string) $failures[0]->note)->not->toContain($garbage);
});

it('rate-limits operator writes per credential with a global ceiling', function (): void {
    $minter = operatorCredential([OperatorAbility::CredentialMint->value]);

    for ($i = 1; $i <= 60; $i++) {
        $this->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'burst-'.$i,
        ], ['Authorization' => $minter->bearerHeader()])->assertCreated();
    }

    // The 61st write from the SAME credential + IP is throttled…
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'burst-61',
    ], ['Authorization' => $minter->bearerHeader()])->assertStatus(429);

    // …while a different operator credential still writes: the key is per
    // operator credential + IP, bounded above by the global ceiling.
    $other = operatorCredential([OperatorAbility::CredentialMint->value]);

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'other-cred',
    ], ['Authorization' => $other->bearerHeader()])->assertCreated();

    // Reads are deliberately not write-throttled.
    $reader = operatorCredential([OperatorAbility::CredentialRead->value]);
    $this->getJson('/bfc/credentials', ['Authorization' => $reader->bearerHeader()])->assertOk();
});
