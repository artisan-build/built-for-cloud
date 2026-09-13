<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/** @return array{credential: Credential, headers: array{Authorization: string}} */
function p5bOperatorCredential(string $ability, SubjectType $subjectType = SubjectType::Operator): array
{
    $plaintext = 'p5b-'.bin2hex(random_bytes(24));
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => $subjectType,
        'subject_ref' => 'p5b-'.bin2hex(random_bytes(4)),
        'abilities' => [$ability],
        'secret_hash' => hash('sha256', $plaintext),
        'status' => CredentialStatus::Active,
    ]);

    return [
        'credential' => $credential,
        'headers' => ['Authorization' => 'Bearer '.$plaintext],
    ];
}

function p5bClaimedOwnership(?OwnershipClaim $pending = null): Ownership
{
    $owner = p5bOperatorCredential(OperatorAbility::ADMIN)['credential'];

    return Ownership::query()->create([
        'owner_credential_id' => $owner->id,
        'pending_claim_id' => $pending?->id,
    ]);
}

function p5bPendingOwnershipClaim(): OwnershipClaim
{
    return OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken('p5b-claim-'.bin2hex(random_bytes(16))),
    ]);
}

it('gates ownership release on the exact unified ownership ability with break-glass', function (): void {
    $ownership = p5bClaimedOwnership();
    $wrong = p5bOperatorCredential(OperatorAbility::CredentialMint->value);
    $nonOperator = p5bOperatorCredential(OperatorAbility::OwnershipRelease->value, SubjectType::Application);

    $this->postJson('/bfc/ownership/release', [], $wrong['headers'])->assertForbidden();
    $this->postJson('/bfc/ownership/release', [], $nonOperator['headers'])->assertForbidden();
    expect($ownership->refresh()->pending_claim_id)->toBeNull();

    $exact = p5bOperatorCredential(OperatorAbility::OwnershipRelease->value);
    $this->postJson('/bfc/ownership/release', [], $exact['headers'])->assertCreated();

    $firstClaim = OwnershipClaim::query()->findOrFail($ownership->refresh()->pending_claim_id);
    expect($firstClaim->consumed_at)->toBeNull();

    $breakGlass = p5bOperatorCredential(OperatorAbility::ADMIN);
    $this->postJson('/bfc/ownership/release', [], $breakGlass['headers'])->assertCreated();

    expect($firstClaim->refresh()->consumed_at)->not->toBeNull()
        ->and($ownership->refresh()->pending_claim_id)->not->toBe($firstClaim->id);
});

it('gates transfer cancellation on the exact unified ownership ability with break-glass', function (): void {
    $pending = p5bPendingOwnershipClaim();
    $ownership = p5bClaimedOwnership($pending);
    $wrong = p5bOperatorCredential(OperatorAbility::CredentialRead->value);
    $nonOperator = p5bOperatorCredential(OperatorAbility::OwnershipRelease->value, SubjectType::Application);

    $this->postJson('/bfc/ownership/cancel-transfer', [], $wrong['headers'])->assertForbidden();
    $this->postJson('/bfc/ownership/cancel-transfer', [], $nonOperator['headers'])->assertForbidden();
    expect($ownership->refresh()->pending_claim_id)->toBe($pending->id)
        ->and($pending->refresh()->consumed_at)->toBeNull();

    $exact = p5bOperatorCredential(OperatorAbility::OwnershipRelease->value);
    $this->postJson('/bfc/ownership/cancel-transfer', [], $exact['headers'])
        ->assertOk()
        ->assertJsonPath('ok', true);
    expect($ownership->refresh()->pending_claim_id)->toBeNull()
        ->and($pending->refresh()->consumed_at)->not->toBeNull();

    $nextPending = p5bPendingOwnershipClaim();
    $ownership->forceFill(['pending_claim_id' => $nextPending->id])->save();
    $breakGlass = p5bOperatorCredential(OperatorAbility::ADMIN);
    $this->postJson('/bfc/ownership/cancel-transfer', [], $breakGlass['headers'])->assertOk();
    expect($ownership->refresh()->pending_claim_id)->toBeNull()
        ->and($nextPending->refresh()->consumed_at)->not->toBeNull();
});

it('gates onboarding issue on credential mint and attributes the unified actor', function (): void {
    $wrong = p5bOperatorCredential(OperatorAbility::CredentialRead->value);
    $nonOperator = p5bOperatorCredential(OperatorAbility::CredentialMint->value, SubjectType::Application);
    $payload = ['ttl_seconds' => 3600];

    $this->postJson('/bfc/onboarding/issue', $payload, $wrong['headers'])->assertForbidden();
    $this->postJson('/bfc/onboarding/issue', $payload, $nonOperator['headers'])->assertForbidden();
    expect(OnboardingToken::query()->count())->toBe(0);

    $exact = p5bOperatorCredential(OperatorAbility::CredentialMint->value);
    $this->postJson('/bfc/onboarding/issue', $payload, $exact['headers'])->assertCreated();
    expect(OnboardingToken::query()->count())->toBe(1);

    $issued = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Issued->value)
        ->latest('created_at')
        ->firstOrFail();
    expect($issued->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($issued->actor_ref)->toBe($exact['credential']->id);

    $breakGlass = p5bOperatorCredential(OperatorAbility::ADMIN);
    $this->postJson('/bfc/onboarding/issue', $payload, $breakGlass['headers'])->assertCreated();
    expect(OnboardingToken::query()->count())->toBe(2);
});

it('serves fixed client observations only to credential readers and break-glass', function (): void {
    $wrong = p5bOperatorCredential(OperatorAbility::CredentialMint->value);
    $nonOperator = p5bOperatorCredential(OperatorAbility::CredentialRead->value, SubjectType::Application);

    $this->getJson('/bfc/client-observations', $wrong['headers'])->assertForbidden();
    $this->getJson('/bfc/client-observations', $nonOperator['headers'])->assertForbidden();

    $exact = p5bOperatorCredential(OperatorAbility::CredentialRead->value);
    $this->getJson('/bfc/client-observations', $exact['headers'])
        ->assertOk()
        ->assertJsonPath('observations', []);
    expect($exact['credential']->refresh()->last_used_at)->not->toBeNull();

    $breakGlass = p5bOperatorCredential(OperatorAbility::ADMIN);
    $this->getJson('/bfc/client-observations', $breakGlass['headers'])->assertOk();
    expect($breakGlass['credential']->refresh()->last_used_at)->not->toBeNull();
});
