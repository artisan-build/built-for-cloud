<?php

declare(strict_types=1);

use ArtisanBuild\BfcClient\Actions\InstallHmacCredentialFromClaim;
use ArtisanBuild\BfcClient\AppPurposeRegistry;
use ArtisanBuild\BfcClient\ConfiguredHmacVerification;
use ArtisanBuild\BfcClient\Contracts\HmacAppPurposeRegistry;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialStore;
use ArtisanBuild\BfcClient\Contracts\HmacVerificationConfiguration;
use ArtisanBuild\BfcClient\CredentialMaterialRole;
use ArtisanBuild\BfcClient\CredentialPurpose as SharedCredentialPurpose;
use ArtisanBuild\BfcClient\CredentialStatus;
use ArtisanBuild\BfcClient\Exceptions\HmacVerificationFailed as SharedHmacVerificationFailed;
use ArtisanBuild\BfcClient\Hmac\HmacEnvelope as SharedHmacEnvelope;
use ArtisanBuild\BfcClient\Hmac\HmacKeyring as SharedHmacKeyring;
use ArtisanBuild\BfcClient\Hmac\HmacVerifier as SharedHmacVerifier;
use ArtisanBuild\BfcClient\StoredHmacCredential;
use ArtisanBuild\BuiltForCloud\Actions\InstallHmacCredentialFromClaim as CompatibleInstallHmacCredentialFromClaim;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Hmac\UnifiedHmacCredentialStore;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('keeps the built-for-cloud compatibility symbols on the client-owned implementations', function (): void {
    $envelope = new HmacEnvelope(
        keyId: '00000000-0000-0000-0000-000000000001',
        eventType: 'test.event',
        timestamp: 1,
        nonce: str_repeat('a', 16),
        audience: 'test-audience',
    );
    $compatibilityFailure = HmacVerificationFailed::wrongAudience();

    expect(CredentialPurpose::Signing)->toBe(SharedCredentialPurpose::Signing)
        ->and($envelope)->toBeInstanceOf(SharedHmacEnvelope::class)
        ->and($compatibilityFailure::class)->toBe(HmacVerificationFailed::class)
        ->and($compatibilityFailure->reason)->toBe('wrong_audience')
        ->and($compatibilityFailure->getPrevious())->toBeInstanceOf(SharedHmacVerificationFailed::class)
        ->and(is_a(
            HmacCredentialIssuerClient::class,
            ArtisanBuild\BfcClient\Contracts\HmacCredentialIssuerClient::class,
            true,
        ))->toBeTrue()
        ->and(app(HmacKeyring::class)->implementation())->toBe(app(SharedHmacKeyring::class))
        ->and(app(HmacVerifier::class))->toBeInstanceOf(HmacVerifier::class)
        ->and(app(CompatibleInstallHmacCredentialFromClaim::class))->toBeInstanceOf(CompatibleInstallHmacCredentialFromClaim::class);
});

it('resolves the shared security algorithms over the unified store adapters', function (): void {
    expect(app(HmacCredentialStore::class))->toBeInstanceOf(UnifiedHmacCredentialStore::class)
        ->and(app(HmacAppPurposeRegistry::class))->not->toBeInstanceOf(AppPurposeRegistry::class)
        ->and(app(HmacVerificationConfiguration::class))->not->toBeInstanceOf(ConfiguredHmacVerification::class)
        ->and(app(SharedHmacKeyring::class))->toBeInstanceOf(SharedHmacKeyring::class)
        ->and(app(SharedHmacVerifier::class))->toBeInstanceOf(SharedHmacVerifier::class)
        ->and(app(InstallHmacCredentialFromClaim::class))->toBeInstanceOf(InstallHmacCredentialFromClaim::class);
});

it('maps every callback-security field from the unified credential store', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $predecessor = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
    ]);
    CredentialProtocolBinding::createVerificationCopy($predecessor, $scope);
    $deliveredAt = now()->subMinutes(2)->startOfSecond();
    $activatedAt = now()->subMinute()->startOfSecond();
    $expiresAt = now()->addHour()->startOfSecond();
    $replacement = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'delivered_at' => $deliveredAt,
        'delivered_generation' => 7,
        'delivery_fingerprint' => '0123456789abcdef',
        'activated_at' => $activatedAt,
        'expires_at' => $expiresAt,
    ]);
    $binding = CredentialProtocolBinding::createVerificationCopy($replacement, $scope);
    DB::transaction(fn () => app(LifecycleEventRecorder::class)->record(
        LifecycleEventType::Rotated,
        $predecessor->id,
        reason: AuditReason::Rotation,
        supersededByCredentialId: $replacement->id,
    ));

    $stored = app(HmacCredentialStore::class)->find($replacement->id)
        ?? throw new LogicException('The unified HMAC credential was not mapped.');

    expect($stored)->toBeInstanceOf(StoredHmacCredential::class)
        ->and($stored->id)->toBe($replacement->id)
        ->and($stored->purpose)->toBe(SharedCredentialPurpose::Signing)
        ->and($stored->subject->type)->toBe($scope->subject->type)
        ->and($stored->subject->ref)->toBe($scope->subject->ref)
        ->and($stored->status)->toBe(CredentialStatus::Active)
        ->and($stored->secretCiphertext)->toBe($replacement->secret_ciphertext)
        ->and($stored->secretKeyVersion)->toBe($replacement->secret_key_version)
        ->and($stored->deliveredAt->getTimestamp())->toBe($deliveredAt->getTimestamp())
        ->and($stored->deliveryGeneration)->toBe(7)
        ->and($stored->deliveryFingerprint)->toBe('0123456789abcdef')
        ->and($stored->predecessorCredentialId)->toBe($predecessor->id)
        ->and($stored->activatedAt->getTimestamp())->toBe($activatedAt->getTimestamp())
        ->and($stored->expiresAt?->getTimestamp())->toBe($expiresAt->getTimestamp())
        ->and($stored->revokedAt)->toBeNull()
        ->and($stored->scope)->toEqual($scope)
        ->and($stored->materialRole)->toBe(CredentialMaterialRole::VerificationCopy)
        ->and($stored->scopeHash)->toBe($binding->scope_hash);
});

it('verifies a server-signed callback through the shared verifier without receiver tables', function (): void {
    Schema::dropIfExists('bfc_client_hmac_bindings');
    Schema::dropIfExists('bfc_client_hmac_credentials');
    expect(Schema::hasTable('bfc_client_hmac_credentials'))->toBeFalse()
        ->and(Schema::hasTable('bfc_client_hmac_bindings'))->toBeFalse();

    $subject = new Subject(SubjectType::ExternalConsumer, 'shared-verifier');
    $credential = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $subject->type,
        'subject_ref' => $subject->ref,
    ]);
    $body = '{"event":"shared.callback"}';
    $header = app(HmacSigner::class)->sign($subject, $body, 'shared.callback');
    $queries = [];
    DB::listen(static function ($query) use (&$queries): void {
        $queries[] = $query->sql;
    });

    $verified = app(SharedHmacVerifier::class)->verify($subject, $header, $body);

    expect($verified->credentialId)->toBe($credential->id)
        ->and($credential->refresh()->last_used_at)->not->toBeNull()
        ->and(implode("\n", $queries))->not->toContain('bfc_client_');

    $tamperedHeader = app(HmacSigner::class)->sign($subject, $body, 'shared.callback');

    try {
        app(SharedHmacVerifier::class)->verify($subject, $tamperedHeader, '{"event":"tampered"}');
        $this->fail('The tampered callback should have been refused.');
    } catch (SharedHmacVerificationFailed $failure) {
        expect($failure->reason)->toBe('invalid_signature');
    }

    $compatibilityHeader = app(HmacSigner::class)->sign($subject, $body, 'shared.callback');

    try {
        app(HmacVerifier::class)->verify($subject, $compatibilityHeader, '{"event":"tampered"}');
        $this->fail('The compatibility verifier should have translated the shared refusal.');
    } catch (HmacVerificationFailed $failure) {
        expect($failure::class)->toBe(HmacVerificationFailed::class)
            ->and($failure->reason)->toBe('invalid_signature')
            ->and($failure->getPrevious())->toBeInstanceOf(SharedHmacVerificationFailed::class);
    }
});
