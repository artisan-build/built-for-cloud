<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\CoordinateImportedHmacCutover;
use ArtisanBuild\BuiltForCloud\Actions\CutOverImportedHmacCredential;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Actions\SourceBoundHmacCutover;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\CrossStoreCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\SensitiveString;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/** @return array{Credential, string} */
function ac3VerificationCopy(BoundCredentialScope $scope, string $key, ?CarbonImmutable $expiry = null, ?string $id = null): array
{
    $encrypted = app(HmacKeyring::class)->encrypt($key);
    $credential = Credential::factory()->hmac()->activated()->create([
        ...($id === null ? [] : ['id' => $id]),
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'expires_at' => $expiry,
    ]);
    CredentialProtocolBinding::createVerificationCopy($credential, $scope);

    return [$credential, $key];
}

function ac3Lineage(Credential $old, Credential $new): void
{
    DB::transaction(fn () => app(LifecycleEventRecorder::class)->record(
        LifecycleEventType::Rotated,
        $old->id,
        reason: AuditReason::Rotation,
        supersededByCredentialId: $new->id,
    ));
}

function ac3Header(Credential $credential, string $key, BoundCredentialScope $scope, string $body): string
{
    $envelope = new HmacEnvelope($credential->id, 'matte.completed', now()->getTimestamp(), bin2hex(random_bytes(16)), $scope->audience);

    return $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $key));
}

it('keeps receiver old and replacement verification overlapping through the authoritative deadline', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    [$old, $oldKey] = ac3VerificationCopy($scope, str_repeat('a', 64));
    [$new, $newKey] = ac3VerificationCopy($scope, str_repeat('b', 64));
    ac3Lineage($old, $new);
    $deadline = CarbonImmutable::now()->startOfSecond()->addMinutes(10);
    $receipt = IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::now(), $deadline, false);

    expect(app(HmacVerifier::class)->verifyBound($scope, ac3Header($old, $oldKey, $scope, 'old'), 'old')->credentialId)->toBe($old->id)
        ->and(app(HmacVerifier::class)->verifyBound($scope, ac3Header($new, $newKey, $scope, 'new'), 'new')->credentialId)->toBe($new->id);

    $auditBefore = CredentialAuditEvent::query()->count();
    $outboxBefore = CredentialOutboxEntry::query()->count();
    app(CutOverImportedHmacCredential::class)($scope, $receipt);
    app(CutOverImportedHmacCredential::class)($scope, $receipt);

    expect($old->refresh()->expires_at?->getTimestamp())->toBe($deadline->getTimestamp())
        ->and(CredentialAuditEvent::query()->count())->toBe($auditBefore + 1)
        ->and(CredentialOutboxEntry::query()->count())->toBe($outboxBefore + 1);

    $this->travelTo($deadline->addSecond());
    expect(fn () => app(HmacVerifier::class)->verifyBound($scope, ac3Header($old, $oldKey, $scope, 'late'), 'late'))
        ->toThrow(HmacVerificationFailed::class)
        ->and(app(HmacVerifier::class)->verifyBound($scope, ac3Header($new, $newKey, $scope, 'new-late'), 'new-late')->credentialId)->toBe($new->id);
});

it('switches source signing only at activation and returns its actual never-extended expiry', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $mint = app(MintCredential::class)($scope->subject, new MintOptions(
        kind: CredentialKind::Hmac,
        purpose: CredentialPurpose::Signing,
        codeTtlSeconds: 3600,
        boundScope: $scope,
    ));
    $firstCode = $mint->secret?->reveal() ?? '';
    $first = $this->postJson('/bfc/onboarding/exchange', ['token' => $firstCode])->assertCreated()->json();
    app(ActivateCredential::class)($mint->summary->id, (string) $first['delivery_fingerprint']);
    $earlier = CarbonImmutable::now()->addMinutes(15);
    Credential::query()->whereKey($mint->summary->id)->update(['expires_at' => $earlier]);
    $rotation = app(RotateCredential::class)($mint->summary->id, new RotateOptions(codeTtlSeconds: 3600));
    $replacementId = (string) $rotation?->mint->summary->id;
    $second = $this->postJson('/bfc/onboarding/exchange', ['token' => $rotation?->mint->secret?->reveal()])->assertCreated()->json();
    [$before] = HmacEnvelope::parse(app(HmacSigner::class)->signBound($scope, 'body', 'event'));
    $receipt = app(SourceBoundHmacCutover::class)->activate($scope, $mint->summary->id, $replacementId, (string) $second['delivery_fingerprint']);
    [$after] = HmacEnvelope::parse(app(HmacSigner::class)->signBound($scope, 'body', 'event'));

    expect($before->keyId)->toBe($mint->summary->id)
        ->and($after->keyId)->toBe($replacementId)
        ->and($receipt->predecessorExpiresAt?->getTimestamp())->toBe($earlier->getTimestamp())
        ->and($receipt->emergency)->toBeFalse()
        ->and(app(SourceBoundHmacCutover::class)->status($scope, $mint->summary->id, $replacementId)->predecessorExpiresAt?->getTimestamp())->toBe($earlier->getTimestamp());
});

it('applies delayed shortening and emergency immediately but refuses extension or mismatched lineage atomically', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    [$old] = ac3VerificationCopy($scope, str_repeat('c', 64), CarbonImmutable::now()->addHours(2));
    [$new] = ac3VerificationCopy($scope, str_repeat('d', 64));
    [$other] = ac3VerificationCopy($scope, str_repeat('e', 64));
    ac3Lineage($old, $new);
    $first = CarbonImmutable::now()->addHour();
    app(CutOverImportedHmacCredential::class)($scope, IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::now(), $first, false));
    $shorter = CarbonImmutable::now()->subSecond();
    app(CutOverImportedHmacCredential::class)($scope, IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::now(), $shorter, true));
    $before = [$old->refresh()->getAttributes(), CredentialAuditEvent::query()->count(), CredentialOutboxEntry::query()->count()];

    foreach ([
        IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::now(), $first, false),
        IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $other->id, $scope, CarbonImmutable::now(), $shorter, true),
    ] as $receipt) {
        expect(fn () => app(CutOverImportedHmacCredential::class)($scope, $receipt))->toThrow(HmacCredentialTransferRefused::class)
            ->and([$old->refresh()->getAttributes(), CredentialAuditEvent::query()->count(), CredentialOutboxEntry::query()->count()])->toBe($before);
    }

    expect($old->expires_at?->getTimestamp())->toBe($shorter->getTimestamp())
        ->and(CredentialAuditEvent::query()->where('reason_code', AuditReason::Emergency)->count())->toBe(1);
});

it('reports a non-secret incomplete cutover and recovers from authenticated status', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    [$old] = ac3VerificationCopy($scope, str_repeat('f', 64));
    [$new] = ac3VerificationCopy($scope, str_repeat('0', 64));
    $deadline = CarbonImmutable::now()->addMinutes(30);
    $receipt = IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::now(), $deadline, false);
    $issuer = new class($receipt) implements HmacCredentialIssuerClient
    {
        public function __construct(private readonly IssuerHmacCutoverReceipt $receipt) {}

        public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential
        {
            throw new LogicException('Not used.');
        }

        public function activate(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId, string $deliveryFingerprint): IssuerHmacCutoverReceipt
        {
            return $this->receipt;
        }

        public function cutoverStatus(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt
        {
            return $this->receipt;
        }
    };

    try {
        app(CoordinateImportedHmacCutover::class)->activate($scope, $issuer, $old->id, $new->id, str_repeat('1', 16));
        $this->fail('Missing durable lineage should leave cross-store cutover incomplete.');
    } catch (CrossStoreCutoverIncomplete $failure) {
        expect($failure->predecessorCredentialId)->toBe($old->id)
            ->and($failure->replacementCredentialId)->toBe($new->id)
            ->and($failure->getMessage())->not->toContain(str_repeat('f', 64), str_repeat('0', 64));
    }

    ac3Lineage($old, $new);
    $result = app(CoordinateImportedHmacCutover::class)->recover($scope, $issuer, $old->id, $new->id);
    expect($result->predecessorExpiresAt->getTimestamp())->toBe($deadline->getTimestamp());
});

it('repairs a committed source activation from a later expiry without extending an earlier deadline', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $receiverConnection = DB::getDefaultConnection();
    $sourceConnection = 'hmac_cutover_source';
    config()->set('database.connections.'.$sourceConnection, [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    DB::purge($sourceConnection);
    Artisan::call('migrate:fresh', [
        '--database' => $sourceConnection,
        '--path' => dirname(__DIR__).'/database/migrations',
        '--realpath' => true,
        '--force' => true,
    ]);

    try {
        DB::setDefaultConnection($sourceConnection);
        $mint = app(MintCredential::class)($scope->subject, new MintOptions(
            kind: CredentialKind::Hmac,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ));
        $first = $this->postJson('/bfc/onboarding/exchange', [
            'token' => $mint->secret?->reveal(),
        ])->assertCreated()->json();
        app(ActivateCredential::class)($mint->summary->id, (string) $first['delivery_fingerprint']);
        $rotation = app(RotateCredential::class)($mint->summary->id, new RotateOptions(codeTtlSeconds: 3600));
        $replacementId = (string) $rotation?->mint->summary->id;
        $second = $this->postJson('/bfc/onboarding/exchange', [
            'token' => $rotation?->mint->secret?->reveal(),
        ])->assertCreated()->json();
        $predecessorId = $mint->summary->id;
        $laterDeadline = CarbonImmutable::now()->startOfSecond()->addHours(2);
        Credential::query()->whereKey($predecessorId)->update(['expires_at' => $laterDeadline]);

        DB::unprepared(<<<SQL
            CREATE TRIGGER fail_hmac_predecessor_retirement
            BEFORE UPDATE OF expires_at ON credentials
            WHEN OLD.id = '{$predecessorId}' AND OLD.expires_at IS NOT NULL AND NEW.expires_at < OLD.expires_at
            BEGIN
                SELECT RAISE(ABORT, 'forced predecessor retirement failure');
            END
            SQL);

        expect(fn () => app(SourceBoundHmacCutover::class)->activate(
            $scope,
            $predecessorId,
            $replacementId,
            (string) $second['delivery_fingerprint'],
        ))->toThrow(RotationCutoverIncomplete::class);

        $activatedAt = Credential::query()->findOrFail($replacementId)->activated_at?->toImmutable();
        expect($activatedAt)->not->toBeNull()
            ->and(Credential::query()->findOrFail($replacementId)->status->value)->toBe('active')
            ->and(Credential::query()->findOrFail($predecessorId)->expires_at?->getTimestamp())->toBe($laterDeadline->getTimestamp());
        DB::unprepared('DROP TRIGGER fail_hmac_predecessor_retirement');

        DB::setDefaultConnection($receiverConnection);
        [$receiverPredecessor] = ac3VerificationCopy($scope, str_repeat('2', 64), $laterDeadline, $predecessorId);
        ac3VerificationCopy($scope, str_repeat('3', 64), id: $replacementId);
        ac3Lineage($receiverPredecessor, Credential::query()->findOrFail($replacementId));

        $issuer = new class($sourceConnection) implements HmacCredentialIssuerClient
        {
            public function __construct(private readonly string $sourceConnection) {}

            public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential
            {
                throw new LogicException('Not used.');
            }

            public function activate(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId, string $deliveryFingerprint): IssuerHmacCutoverReceipt
            {
                throw new LogicException('Not used.');
            }

            public function cutoverStatus(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt
            {
                $receiverConnection = DB::getDefaultConnection();
                DB::setDefaultConnection($this->sourceConnection);

                try {
                    return app(SourceBoundHmacCutover::class)->status($expectedScope, $predecessorId, $replacementId);
                } finally {
                    DB::setDefaultConnection($receiverConnection);
                }
            }
        };

        $result = app(CoordinateImportedHmacCutover::class)->recover(
            $scope,
            $issuer,
            $predecessorId,
            $replacementId,
        );
        $expectedDeadline = $activatedAt?->addSeconds(RotateCredential::GRACE_SECONDS);

        expect($result->predecessorExpiresAt->getTimestamp())->toBe($expectedDeadline?->getTimestamp())
            ->and($receiverPredecessor->refresh()->expires_at?->getTimestamp())->toBe($expectedDeadline?->getTimestamp());

        DB::setDefaultConnection($sourceConnection);
        expect(Credential::query()->findOrFail($predecessorId)->expires_at?->getTimestamp())->toBe($expectedDeadline?->getTimestamp())
            ->and(fn () => app(SourceBoundHmacCutover::class)->activate(
                $scope,
                $predecessorId,
                $replacementId,
                (string) $second['delivery_fingerprint'],
            ))->toThrow(HmacCredentialTransferRefused::class)
            ->and(Credential::query()->findOrFail($predecessorId)->expires_at?->getTimestamp())->toBe($expectedDeadline?->getTimestamp());

        $earlierDeadline = $expectedDeadline?->subMinutes(10);
        Credential::query()->whereKey($predecessorId)->update(['expires_at' => $earlierDeadline]);
        DB::setDefaultConnection($receiverConnection);
        Credential::query()->whereKey($predecessorId)->update(['expires_at' => $earlierDeadline]);
        $earlierResult = app(CoordinateImportedHmacCutover::class)->recover(
            $scope,
            $issuer,
            $predecessorId,
            $replacementId,
        );

        expect($earlierResult->predecessorExpiresAt->getTimestamp())->toBe($earlierDeadline?->getTimestamp())
            ->and($receiverPredecessor->refresh()->expires_at?->getTimestamp())->toBe($earlierDeadline?->getTimestamp());
        DB::setDefaultConnection($sourceConnection);
        expect(Credential::query()->findOrFail($predecessorId)->expires_at?->getTimestamp())->toBe($earlierDeadline?->getTimestamp());
    } finally {
        DB::setDefaultConnection($receiverConnection);
        DB::purge($sourceConnection);
    }
});

it('refuses imported verification copies as both bound and legacy signers', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    ac3VerificationCopy($scope, str_repeat('1', 64));

    expect(fn () => app(HmacSigner::class)->signBound($scope, 'body', 'event'))
        ->toThrow(HmacSigningRefused::class)
        ->and(fn () => app(HmacSigner::class)->sign($scope->subject, 'body', 'event'))
        ->toThrow(HmacSigningRefused::class);
});
