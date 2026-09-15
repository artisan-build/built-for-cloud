<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\InstallHmacCredentialFromClaim;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\HmacCredentialTransfer;
use ArtisanBuild\BuiltForCloud\ImportedHmacSecret;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\SensitiveString;
use ArtisanBuild\BuiltForCloud\Subject;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** @param array<string, mixed> $changes */
function ac1Claimed(BoundCredentialScope $scope, string $key, array $changes = []): ClaimedHmacCredential
{
    $generation = (int) ($changes['generation'] ?? 3);
    $delivered = CarbonImmutable::now()->startOfSecond();
    $facts = array_merge([
        'id' => (string) Str::uuid(),
        'scope' => $scope,
        'algorithm' => 'hmac-sha256',
        'credential_expiry' => CarbonImmutable::now()->addDay(),
        'generation' => $generation,
        'fingerprint' => app(HmacKeyring::class)->deliveryFingerprint($key, $generation),
        'predecessor' => null,
        'status' => CredentialStatus::Pending,
        'delivered' => $delivered,
        'transfer_expiry' => $delivered->addSeconds(60),
        'key' => $key,
    ], $changes);

    return ClaimedHmacCredential::fromIssuerResponse(
        HmacCredentialTransfer::fromIssuerResponse(
            $facts['id'],
            $facts['scope'],
            $facts['algorithm'],
            $facts['credential_expiry'],
            $facts['generation'],
            $facts['fingerprint'],
            $facts['predecessor'],
            $facts['status'],
            $facts['delivered'],
            $facts['transfer_expiry'],
        ),
        ImportedHmacSecret::fromIssuerResponse($facts['key']),
    );
}

function ac1Issuer(ClaimedHmacCredential $claimed): HmacCredentialIssuerClient
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
            throw new LogicException('Not used.');
        }

        public function cutoverStatus(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt
        {
            throw new LogicException('Not used.');
        }
    };
}

/** @return array{credentials: int, bindings: int, audit: int, outbox: int} */
function ac1State(): array
{
    return [
        'credentials' => Credential::query()->count(),
        'bindings' => CredentialProtocolBinding::query()->count(),
        'audit' => CredentialAuditEvent::query()->count(),
        'outbox' => CredentialOutboxEntry::query()->count(),
    ];
}

it('refuses every malformed or dead transfer fact without partial receiver state', function (): void {
    testsConfigureBoundPurposes();
    config()->set('built-for-cloud.credentials.app_purposes.other.callback', CredentialPurpose::Signing->value);
    config()->push('built-for-cloud.ui.credential_purposes', 'other.callback');
    $scope = testsBoundScope('matte.callback');
    $key = str_repeat('a', 64);
    $wrongSubject = new BoundCredentialScope($scope->appPurpose, new Subject($scope->subject->type, 'other-subject'), $scope->installation, $scope->application, $scope->audience);
    $wrongPurpose = new BoundCredentialScope('other.callback', $scope->subject, $scope->installation, $scope->application, $scope->audience);
    $wrongInstallation = new BoundCredentialScope($scope->appPurpose, $scope->subject, 'other-install', $scope->application, $scope->audience);
    $wrongApplication = new BoundCredentialScope($scope->appPurpose, $scope->subject, $scope->installation, 'other-app', $scope->audience);
    $wrongAudience = new BoundCredentialScope($scope->appPurpose, $scope->subject, $scope->installation, $scope->application, 'https://other.example');
    $cases = [
        'wrong subject' => ['scope' => $wrongSubject],
        'wrong app purpose' => ['scope' => $wrongPurpose],
        'wrong installation' => ['scope' => $wrongInstallation],
        'wrong application' => ['scope' => $wrongApplication],
        'wrong audience' => ['scope' => $wrongAudience],
        'wrong algorithm' => ['algorithm' => 'RS256'],
        'zero generation' => ['generation' => 0, 'fingerprint' => str_repeat('0', 16)],
        'malformed fingerprint' => ['fingerprint' => str_repeat('0', 15)],
        'changed fingerprint' => ['fingerprint' => str_repeat('0', 16)],
        'malformed key' => ['key' => str_repeat('g', 64)],
        'future delivery' => ['delivered' => CarbonImmutable::now()->addSecond(), 'transfer_expiry' => CarbonImmutable::now()->addSeconds(60)],
        'stale delivery' => ['delivered' => CarbonImmutable::now()->subMinutes(2), 'transfer_expiry' => CarbonImmutable::now()->subMinute()],
        'overlong transfer window' => ['delivered' => CarbonImmutable::now(), 'transfer_expiry' => CarbonImmutable::now()->addSeconds(61)],
        'expired credential' => ['credential_expiry' => CarbonImmutable::now()->subSecond()],
        'active source' => ['status' => CredentialStatus::Active],
        'missing predecessor' => ['predecessor' => (string) Str::uuid()],
        'invalid issuer id' => ['id' => 'not-a-uuid'],
    ];

    foreach ($cases as $label => $changes) {
        $before = ac1State();

        expect(fn () => app(InstallHmacCredentialFromClaim::class)(
            $scope,
            ac1Issuer(ac1Claimed($scope, $key, $changes)),
            str_repeat('c', 64),
        ))->toThrow(HmacCredentialTransferRefused::class);

        expect(ac1State())->toBe($before, $label);
    }
});

it('refuses wrong predecessor state scope generation and collisions without overwriting anything', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $key = str_repeat('b', 64);
    $encrypted = app(HmacKeyring::class)->encrypt(str_repeat('c', 64));
    $predecessor = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'delivered_generation' => 4,
        'delivery_fingerprint' => app(HmacKeyring::class)->deliveryFingerprint(str_repeat('c', 64), 4),
    ]);
    CredentialProtocolBinding::createVerificationCopy($predecessor, $scope);
    $before = ac1State();

    foreach ([
        'backwards generation' => ['predecessor' => $predecessor->id, 'generation' => 3],
        'wrong predecessor scope' => ['predecessor' => $predecessor->id, 'scope' => new BoundCredentialScope($scope->appPurpose, $scope->subject, 'wrong', $scope->application, $scope->audience)],
    ] as $label => $changes) {
        expect(fn () => app(InstallHmacCredentialFromClaim::class)(
            $scope,
            ac1Issuer(ac1Claimed($scope, $key, $changes)),
            str_repeat('d', 64),
        ))->toThrow(HmacCredentialTransferRefused::class);
        expect(ac1State())->toBe($before, $label);
    }

    $collision = ac1Claimed($scope, $key, ['id' => $predecessor->id]);
    $attributes = $predecessor->refresh()->getAttributes();
    ksort($attributes);
    expect(fn () => app(InstallHmacCredentialFromClaim::class)($scope, ac1Issuer($collision), str_repeat('d', 64)))
        ->toThrow(HmacCredentialTransferRefused::class);
    $current = $predecessor->refresh()->getAttributes();
    ksort($current);
    expect($current)->toBe($attributes)
        ->and(ac1State())->toBe($before);
});

it('keeps exact installation idempotence free of decrypt rewrite and duplicate audit', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $key = str_repeat('d', 64);
    $id = (string) Str::uuid();
    $first = ac1Claimed($scope, $key, ['id' => $id]);
    app(InstallHmacCredentialFromClaim::class)($scope, ac1Issuer($first), str_repeat('e', 64));
    $stored = Credential::query()->findOrFail($id);
    $ciphertext = $stored->secret_ciphertext;
    $before = ac1State();

    $again = app(InstallHmacCredentialFromClaim::class)(
        $scope,
        ac1Issuer(ac1Claimed($scope, $key, ['id' => $id])),
        str_repeat('e', 64),
    );

    expect($again->credentialId)->toBe($id)
        ->and($stored->refresh()->secret_ciphertext)->toBe($ciphertext)
        ->and(ac1State())->toBe($before);

    foreach ([
        'changed key with stored descriptor' => str_repeat('f', 64),
        'malformed key with stored descriptor' => str_repeat('g', 64),
    ] as $label => $repeatedKey) {
        expect(fn () => app(InstallHmacCredentialFromClaim::class)(
            $scope,
            ac1Issuer(ac1Claimed($scope, $repeatedKey, [
                'id' => $id,
                'fingerprint' => $stored->delivery_fingerprint,
            ])),
            str_repeat('e', 64),
        ))->toThrow(HmacCredentialTransferRefused::class);
        expect(ac1State())->toBe($before, $label);
    }

    expect(fn () => app(InstallHmacCredentialFromClaim::class)(
        $scope,
        ac1Issuer(ac1Claimed($scope, $key, ['id' => $id, 'fingerprint' => str_repeat('1', 16)])),
        str_repeat('e', 64),
    ))->toThrow(HmacCredentialTransferRefused::class);
    expect(ac1State())->toBe($before);
});

it('commits no receiver state when the HMAC writer barrier cannot be acquired', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $before = ac1State();
    $lock = Cache::lock(HmacWriterBarrier::LOCK, 10);
    expect($lock->get())->toBeTrue();

    try {
        expect(fn () => app(InstallHmacCredentialFromClaim::class)(
            $scope,
            ac1Issuer(ac1Claimed($scope, str_repeat('a', 64))),
            str_repeat('e', 64),
        ))->toThrow(RewrapInProgress::class)
            ->and(ac1State())->toBe($before);
    } finally {
        $lock->release();
    }
});

it('seals transfer carriers and model-free results against serialization', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $claimed = ac1Claimed($scope, str_repeat('a', 64));

    expect(fn () => serialize($claimed))->toThrow(LogicException::class)
        ->and(fn () => json_encode($claimed, JSON_THROW_ON_ERROR))->toThrow(LogicException::class)
        ->and(fn () => serialize($claimed->transfer))->toThrow(LogicException::class)
        ->and(fn () => json_encode($claimed->secret, JSON_THROW_ON_ERROR))->toThrow(LogicException::class);
});
