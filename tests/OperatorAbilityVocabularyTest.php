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
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

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
        ->and(OperatorAbility::ConsoleKeyWrite->value)->toBe('console:key:write')
        ->and(OperatorAbility::McpRead->value)->toBe('mcp:read')
        ->and(OperatorAbility::MetadataRead->value)->toBe('metadata:read')
        ->and(OperatorAbility::ADMIN)->toBe(EnsureCredentialAdmin::ABILITY)
        ->and(OperatorAbility::adminEquivalent())->toBe([
            OperatorAbility::CredentialRead,
            OperatorAbility::CredentialMint,
            OperatorAbility::CredentialRotate,
            OperatorAbility::CredentialRevoke,
            OperatorAbility::SubjectOffboard,
            OperatorAbility::AuditRead,
            // Console key custody is admin-equivalent (the break-glass
            // is a marking someone chose) but is NOT in any other
            // family — `credential:rotate` in particular does not reach
            // it (rework B2).
            OperatorAbility::ConsoleKeyWrite,
        ]);

    // `metadata:read` is now a real case (Console PRD D16) — and it is
    // the one ability the break-glass does NOT reach. Its absence from
    // adminEquivalent() is asserted above by the exact list; asserted
    // here as the property itself, because that is the decision:
    // FORBIDDEN to use the ownership/admin credential for a dashboard
    // read path.
    expect(OperatorAbility::tryFrom('metadata:read'))->toBe(OperatorAbility::MetadataRead)
        ->and(OperatorAbility::adminEquivalent())->not->toContain(OperatorAbility::MetadataRead);
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

it('rate-limits operator writes per credential AND per IP independently (Fix 5)', function (): void {
    $minter = operatorCredential([OperatorAbility::CredentialMint->value]);

    for ($i = 1; $i <= 60; $i++) {
        $this->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'burst-'.$i,
        ], ['Authorization' => $minter->bearerHeader()])->assertCreated();
    }

    // The 61st write from the same credential is throttled — from the
    // SAME IP…
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'burst-61',
    ], ['Authorization' => $minter->bearerHeader()])->assertStatus(429);

    // …and from a DIFFERENT IP: a stolen credential is bounded across
    // every address it is replayed from (the per-credential bucket).
    $this->withServerVariables(['REMOTE_ADDR' => '10.1.1.1'])
        ->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'burst-ip-hop',
        ], ['Authorization' => $minter->bearerHeader()])->assertStatus(429);

    // A different credential from the EXHAUSTED IP is throttled too (the
    // per-IP bucket — a fresh bearer string buys no fresh budget)…
    $other = operatorCredential([OperatorAbility::CredentialMint->value]);

    $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
        ->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'other-cred-same-ip',
        ], ['Authorization' => $other->bearerHeader()])->assertStatus(429);

    // …while the same different credential from a fresh IP writes: the
    // two bounds are independent, not one compound bucket.
    $this->withServerVariables(['REMOTE_ADDR' => '10.2.2.2'])
        ->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'other-cred-fresh-ip',
        ], ['Authorization' => $other->bearerHeader()])->assertCreated();

    // Reads are deliberately not write-throttled.
    $reader = operatorCredential([OperatorAbility::CredentialRead->value]);
    $this->getJson('/bfc/credentials', ['Authorization' => $reader->bearerHeader()])->assertOk();
});

it('bounds invalid-bearer rotation from one IP by the per-IP bucket (Fix 5)', function (): void {
    // Sixty distinct garbage bearers from one address: each gets its own
    // per-credential bucket, but they all share the ONE per-IP bucket…
    for ($i = 1; $i <= 60; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.3.3.3'])
            ->postJson('/bfc/credentials', [
                'subject_type' => 'external_consumer',
                'subject_ref' => 'x',
            ], ['Authorization' => 'Bearer invalid-'.$i.'-'.bin2hex(random_bytes(8))])
            ->assertUnauthorized();
    }

    // …so the 61st rotated bearer is throttled before it even reaches
    // the auth gate.
    $this->withServerVariables(['REMOTE_ADDR' => '10.3.3.3'])
        ->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'x',
        ], ['Authorization' => 'Bearer invalid-61-'.bin2hex(random_bytes(8))])
        ->assertStatus(429);
});

it('registers the three independent operator-write limits, global ceiling included', function (): void {
    // Unit-level, so deleting any bound — the 600/min global ceiling in
    // particular — turns this red without 600 HTTP requests.
    $limiter = RateLimiter::limiter('bfc-operator-write');

    expect($limiter)->not->toBeNull();

    $request = Request::create('/bfc/credentials', 'POST', server: [
        'REMOTE_ADDR' => '9.9.9.9',
        'HTTP_AUTHORIZATION' => 'Bearer probe-secret',
    ]);

    /** @var list<Limit> $limits */
    $limits = $limiter($request);

    expect($limits)->toHaveCount(3);

    $byKey = collect($limits)->keyBy(fn (Limit $limit): string => (string) $limit->key);

    // Per credential: keyed on the presented bearer's sha256, 60/min.
    $credentialKey = 'bfc-op-cred|'.hash('sha256', 'probe-secret');
    expect($byKey->has($credentialKey))->toBeTrue()
        ->and($byKey->get($credentialKey)->maxAttempts)->toBe(60);

    // Per IP: 60/min.
    expect($byKey->has('bfc-op-ip|9.9.9.9'))->toBeTrue()
        ->and($byKey->get('bfc-op-ip|9.9.9.9')->maxAttempts)->toBe(60);

    // The global ceiling: one shared bucket, 600/min.
    expect($byKey->has('bfc-operator-write-global'))->toBeTrue()
        ->and($byKey->get('bfc-operator-write-global')->maxAttempts)->toBe(600);
});
