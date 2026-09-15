<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\CutOverImportedHmacCredential;
use ArtisanBuild\BuiltForCloud\Actions\InstallHmacCredentialFromClaim;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\HmacCredentialTransfer;
use ArtisanBuild\BuiltForCloud\HttpHmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\ImportedHmacSecret;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\SensitiveString;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

/** @return array{BoundCredentialScope, string, string} */
function boundHmacDelivery(): array
{
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Hmac,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );
    $code = $mint->secret?->reveal() ?? '';
    $response = test()->postJson('/bfc/onboarding/exchange', ['token' => $code, 'version' => 1])->assertCreated();

    return [$scope, $code, (string) $response->getContent()];
}

/** @param array<string, mixed> $payload */
function claimedFromPayload(BoundCredentialScope $scope, array $payload): ClaimedHmacCredential
{
    $transfer = HmacCredentialTransfer::fromIssuerResponse(
        (string) $payload['credential_id'],
        $scope,
        (string) $payload['algorithm'],
        is_string($payload['credential_expires_at']) ? CarbonImmutable::parse($payload['credential_expires_at']) : null,
        (int) $payload['delivery_generation'],
        (string) $payload['delivery_fingerprint'],
        is_string($payload['predecessor_credential_id']) ? $payload['predecessor_credential_id'] : null,
        CredentialStatus::from((string) $payload['source_status']),
        CarbonImmutable::parse((string) $payload['delivered_at']),
        CarbonImmutable::parse((string) $payload['transfer_expires_at']),
    );

    return ClaimedHmacCredential::fromIssuerResponse(
        $transfer,
        ImportedHmacSecret::fromIssuerResponse((string) $payload['signing_key']),
    );
}

function issuerReturning(ClaimedHmacCredential $claimed): HmacCredentialIssuerClient
{
    return new class($claimed) implements HmacCredentialIssuerClient
    {
        public function __construct(private readonly ClaimedHmacCredential $claimed) {}

        public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential
        {
            $claimCode->reveal();

            return $this->claimed;
        }

        public function activate(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId, string $deliveryFingerprint): IssuerHmacCutoverReceipt
        {
            throw new LogicException('Not used by this test.');
        }

        public function cutoverStatus(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt
        {
            throw new LogicException('Not used by this test.');
        }
    };
}

function migrateHmacReceiver(): void
{
    config()->set('database.connections.hmac_receiver', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    DB::purge('hmac_receiver');
    Artisan::call('migrate:fresh', [
        '--database' => 'hmac_receiver',
        '--path' => dirname(__DIR__).'/database/migrations',
        '--realpath' => true,
        '--force' => true,
    ]);
}

it('delivers a bound HMAC descriptor once and leaves legacy unbound response bytes unchanged', function (): void {
    [$scope, $code, $body] = boundHmacDelivery();
    $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);

    expect(array_keys($payload))->toBe([
        'signing_key', 'credential_id', 'app_purpose', 'subject_type', 'subject_ref',
        'installation_ref', 'application_ref', 'audience', 'algorithm', 'credential_expires_at',
        'delivery_generation', 'delivery_fingerprint', 'predecessor_credential_id', 'source_status',
        'delivered_at', 'transfer_expires_at',
    ])->and($payload['app_purpose'])->toBe($scope->appPurpose)
        ->and($payload['algorithm'])->toBe('hmac-sha256')
        ->and($payload['source_status'])->toBe('pending')
        ->and($payload)->not->toHaveKeys(['key_id', 'kind', 'status', 'durable_token']);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code, 'version' => 1])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');

    $unbound = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::Signing, codeTtlSeconds: 3600),
    );
    $legacy = $this->postJson('/bfc/onboarding/exchange', ['token' => $unbound->secret?->reveal()])->assertCreated();

    expect(array_keys((array) $legacy->json()))->toBe(['signing_key', 'key_id', 'kind', 'status', 'delivery_fingerprint']);
});

it('pins the HTTP issuer origin and rejects unknown, oversized, and non-JSON response shapes', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $secret = str_repeat('a', 64);
    $payload = [
        'signing_key' => $secret,
        'credential_id' => (string) Illuminate\Support\Str::uuid(),
        'app_purpose' => $scope->appPurpose,
        'subject_type' => $scope->subject->type->value,
        'subject_ref' => $scope->subject->ref,
        'installation_ref' => $scope->installation,
        'application_ref' => $scope->application,
        'audience' => $scope->audience,
        'algorithm' => 'hmac-sha256',
        'credential_expires_at' => null,
        'delivery_generation' => 1,
        'delivery_fingerprint' => app(HmacKeyring::class)->deliveryFingerprint($secret, 1),
        'predecessor_credential_id' => null,
        'source_status' => 'pending',
        'delivered_at' => now()->toRfc3339String(),
        'transfer_expires_at' => now()->addSeconds(60)->toRfc3339String(),
    ];
    Http::fakeSequence()
        ->push($payload, 201, ['Content-Type' => 'application/json'])
        ->push($payload + ['unknown' => true], 201, ['Content-Type' => 'application/json'])
        ->push(str_repeat('x', 24 * 1024 + 1), 201, ['Content-Type' => 'application/json']);
    $client = new HttpHmacCredentialIssuerClient(app(Factory::class), 'https://issuer.example', static fn (): array => ['Authorization' => 'Bearer protected']);

    expect($client->claim($scope, new SensitiveString(str_repeat('b', 64)))->transfer->scope)->toEqual($scope);

    foreach (range(1, 2) as $attempt) {
        expect(fn () => $client->claim($scope, new SensitiveString(str_repeat('c', 64))))
            ->toThrow(HmacCredentialTransferRefused::class);
    }

    expect(fn () => new HttpHmacCredentialIssuerClient(app(Factory::class), 'http://issuer.example', static fn (): array => ['Authorization' => 'x']))
        ->toThrow(HmacCredentialTransferRefused::class);
});

it('installs across separate SQLite stores encrypted and verifies a source-bound signature without exposing a model', function (): void {
    [$scope, , $body] = boundHmacDelivery();
    $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    $sourceConnection = DB::getDefaultConnection();
    $sourceAppKey = (string) config('app.key');
    migrateHmacReceiver();

    try {
        DB::setDefaultConnection('hmac_receiver');
        config()->set('app.key', 'base64:'.base64_encode(str_repeat('r', 32)));
        $installed = app(InstallHmacCredentialFromClaim::class)(
            $scope,
            issuerReturning(claimedFromPayload($scope, $payload)),
            str_repeat('d', 64),
        );
        $receiver = Credential::query()->findOrFail($installed->credentialId);
        $binding = CredentialProtocolBinding::query()->findOrFail($installed->credentialId);

        expect($installed)->not->toBeInstanceOf(Credential::class)
            ->and($receiver->secret_ciphertext)->not->toBe($payload['signing_key'])
            ->and(DB::table('credentials')->where('id', $receiver->id)->value('secret_hash'))->toBeNull()
            ->and($binding->material_role)->toBe(CredentialMaterialRole::VerificationCopy)
            ->and(CredentialAuditEvent::query()->where('credential_id', $receiver->id)->pluck('event')->map->value->all())
            ->toBe(['issued', 'delivered', 'activated']);

        $again = app(InstallHmacCredentialFromClaim::class)(
            $scope,
            issuerReturning(claimedFromPayload($scope, $payload)),
            str_repeat('d', 64),
        );
        expect($again->credentialId)->toBe($installed->credentialId)
            ->and(CredentialAuditEvent::query()->where('credential_id', $receiver->id)->count())->toBe(3);

        DB::setDefaultConnection($sourceConnection);
        config()->set('app.key', $sourceAppKey);
        app(ActivateCredential::class)((string) $payload['credential_id'], (string) $payload['delivery_fingerprint']);
        $header = app(HmacSigner::class)->signBound($scope, 'callback-body', 'matte.completed');
        config()->set('built-for-cloud.hmac.audience', $scope->audience);

        expect(fn () => app(HmacSigner::class)->sign($scope->subject, 'body', 'event'))
            ->toThrow(HmacSigningRefused::class)
            ->and(fn () => app(HmacVerifier::class)->verify($scope->subject, $header, 'callback-body', $scope->audience))
            ->toThrow(ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed::class);

        DB::setDefaultConnection('hmac_receiver');
        config()->set('app.key', 'base64:'.base64_encode(str_repeat('r', 32)));
        $verified = app(HmacVerifier::class)->verifyBound($scope, $header, 'callback-body');

        expect($verified->credentialId)->toBe($installed->credentialId)
            ->and($verified)->not->toBeInstanceOf(Credential::class)
            ->and(fn () => app(HmacSigner::class)->signBound($scope, 'body', 'event'))->toThrow(HmacSigningRefused::class)
            ->and(fn () => app(HmacSigner::class)->sign($scope->subject, 'body', 'event'))->toThrow(HmacSigningRefused::class);
    } finally {
        DB::setDefaultConnection($sourceConnection);
        config()->set('app.key', $sourceAppKey);
        DB::purge('hmac_receiver');
    }
});

it('honors the declared installation app-purpose allow-list before receiver installation', function (): void {
    [$scope, , $body] = boundHmacDelivery();
    $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    config()->set('built-for-cloud.ui.credential_purposes', []);

    expect(fn () => app(InstallHmacCredentialFromClaim::class)(
        $scope,
        issuerReturning(claimedFromPayload($scope, $payload)),
        str_repeat('d', 64),
    ))->toThrow(ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput::class)
        ->and(Credential::query()->whereKey($payload['credential_id'])->count())->toBe(1);
});

it('reissues a lost bound HMAC delivery under the writer barrier without same-second lineage ambiguity', function (): void {
    [$scope, , $body] = boundHmacDelivery();
    $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    app(ActivateCredential::class)((string) $payload['credential_id'], (string) $payload['delivery_fingerprint']);
    $rotation = app(RotateCredential::class)(
        (string) $payload['credential_id'],
        new RotateOptions(codeTtlSeconds: 3600),
    );
    expect($rotation)->not->toBeNull();
    $lostCode = $rotation->mint->secret?->reveal() ?? '';
    $lost = $this->postJson('/bfc/onboarding/exchange', ['token' => $lostCode])->assertCreated();
    $lostId = (string) $lost->json('credential_id');

    $reissued = app(RotateCredential::class)(
        (string) $payload['credential_id'],
        new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true),
    );

    expect($reissued->mint->summary->id)->not->toBe($lostId)
        ->and(Credential::query()->findOrFail($lostId)->revoked_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $lostId)
            ->where('reason_code', AuditReason::DeliveryAbandoned->value)
            ->exists())->toBeTrue()
        ->and(OnboardingToken::query()->where('durable_credential_id', $reissued->mint->summary->id)->whereNull('consumed_at')->exists())->toBeTrue();

    $lock = Cache::lock(ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier::LOCK, 10);
    expect($lock->get())->toBeTrue();

    try {
        expect(fn () => app(RotateCredential::class)(
            (string) $payload['credential_id'],
            new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true),
        ))->toThrow(ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress::class);
    } finally {
        $lock->release();
    }
});

it('serves protected source activation and idempotent status receipts with exact stored expiry', function (): void {
    [$scope, , $body] = boundHmacDelivery();
    $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    $request = [
        'app_purpose' => $scope->appPurpose,
        'subject_type' => $scope->subject->type->value,
        'subject_ref' => $scope->subject->ref,
        'installation_ref' => $scope->installation,
        'application_ref' => $scope->application,
        'audience' => $scope->audience,
        'predecessor_credential_id' => null,
        'replacement_credential_id' => $payload['credential_id'],
    ];
    $headers = ['Authorization' => 'Bearer '.auditOperatorCredential('hmac-cutover-source')];
    $activated = $this->postJson('/bfc/hmac-cutovers/activate', $request + [
        'delivery_fingerprint' => $payload['delivery_fingerprint'],
    ], $headers)->assertOk();

    expect($activated->json('replacement_credential_id'))->toBe($payload['credential_id'])
        ->and($activated->json('predecessor_expires_at'))->toBeNull()
        ->and($activated->headers->get('Cache-Control'))->toContain('no-store');

    $this->postJson('/bfc/hmac-cutovers/status', $request, $headers)
        ->assertOk()
        ->assertExactJson((array) $activated->json());

    $this->postJson('/bfc/hmac-cutovers/status', $request + ['unknown' => true], $headers)->assertStatus(409);
    $this->postJson('/bfc/hmac-cutovers/status', $request)->assertUnauthorized();
});

it('refuses a wrong bound verification scope before decrypt replay rate or usage mutation', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $key = str_repeat('e', 64);
    $encrypted = app(HmacKeyring::class)->encrypt($key);
    $credential = new Credential;
    $credential->forceFill([
        'kind' => CredentialKind::Hmac,
        'purpose' => CredentialPurpose::Signing,
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'status' => CredentialStatus::Active,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'activated_at' => now(),
    ])->save();
    CredentialProtocolBinding::createVerificationCopy($credential, $scope);
    $header = (new ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope(
        $credential->id,
        'event',
        now()->getTimestamp(),
        str_repeat('f', 32),
        $scope->audience,
    ))->headerValue(hash_hmac('sha256', "v1\nevent\n".now()->getTimestamp()."\n".str_repeat('f', 32)."\n{$scope->audience}\n".hash('sha256', 'body'), $key));
    DB::table('credentials')->where('id', $credential->id)->update(['secret_key_version' => 'must-not-decrypt']);
    $wrong = new BoundCredentialScope($scope->appPurpose, $scope->subject, 'wrong-install', $scope->application, $scope->audience);

    expect(fn () => app(HmacVerifier::class)->verifyBound($wrong, $header, 'body'))
        ->toThrow(ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed::class)
        ->and(Cache::has('bfc:hmac:rate:'.$credential->id))->toBeFalse()
        ->and($credential->refresh()->last_used_at)->toBeNull();
});

it('applies only same-lineage receiver deadlines that preserve or shorten authority', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $old = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'expires_at' => now()->addHours(2),
    ]);
    $new = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
    ]);
    CredentialProtocolBinding::createVerificationCopy($old, $scope);
    CredentialProtocolBinding::createVerificationCopy($new, $scope);
    DB::transaction(fn () => app(LifecycleEventRecorder::class)->record(
        LifecycleEventType::Rotated,
        $old->id,
        reason: AuditReason::Rotation,
        supersededByCredentialId: $new->id,
    ));
    $firstDeadline = CarbonImmutable::instance(now()->addHour());
    $first = IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::instance(now()), $firstDeadline, false);

    expect(app(CutOverImportedHmacCredential::class)($scope, $first)->predecessorExpiresAt->equalTo($firstDeadline))->toBeTrue();

    $shorter = $firstDeadline->subMinutes(10);
    $shortReceipt = IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::instance(now()), $shorter, false);
    app(CutOverImportedHmacCredential::class)($scope, $shortReceipt);

    expect($old->refresh()->expires_at->getTimestamp())->toBe($shorter->getTimestamp())
        ->and(fn () => app(CutOverImportedHmacCredential::class)(
            $scope,
            IssuerHmacCutoverReceipt::fromIssuerResponse($old->id, $new->id, $scope, CarbonImmutable::instance(now()), $firstDeadline, false),
        ))->toThrow(HmacCredentialTransferRefused::class);
});
