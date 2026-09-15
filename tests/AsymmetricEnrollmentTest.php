<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\CompleteAsymmetricEnrollment;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AsymmetricVerificationKey;
use ArtisanBuild\BuiltForCloud\AsymmetricVerificationKeys;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\AsymmetricEnrollmentUnavailable;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

uses(RefreshDatabase::class, ContractAssertions::class, WithCredentials::class);

/** @return array{scope: BoundCredentialScope, code: string, id: string} */
function pendingBoundEnrollment(): array
{
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );

    return [
        'scope' => $scope,
        'code' => $mint->secret?->reveal() ?? '',
        'id' => $mint->summary->id,
    ];
}

function bindEnrollmentScope(BoundCredentialScope $scope): void
{
    app()->instance(ResolvesAsymmetricEnrollmentScope::class, new class($scope) implements ResolvesAsymmetricEnrollmentScope
    {
        public function __construct(private readonly BoundCredentialScope $scope) {}

        public function resolve(Request $request, string $application): ?BoundCredentialScope
        {
            return $application === $this->scope->application ? $this->scope : null;
        }
    });
}

/** @return array<string, string> */
function asymmetricRotationHeaders(): array
{
    $credential = test()->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'asymmetric-rotation-operator',
        'abilities' => [OperatorAbility::CredentialRotate->value],
    ]);

    return ['Authorization' => $credential->bearerHeader()];
}

it('completes the exact public-only enrollment over HTTP and verifies retained-private-key bytes', function (): void {
    $pending = pendingBoundEnrollment();
    $key = testsRsaKey();
    bindEnrollmentScope($pending['scope']);
    Log::spy();

    $response = $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => " \r\n".str_replace("\n", "\r\n", $key['public'])."\t ",
    ])->assertCreated()->assertExactJson([
        'credential_id' => $pending['id'],
        'algorithm' => 'RS256',
    ]);
    $this->assertBuiltForCloudMetadataEndpoint($response, 'POST /bfc/asymmetric-enrollments/{application}');

    $credential = Credential::query()->findOrFail($pending['id']);
    $token = OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole();
    $events = CredentialAuditEvent::query()->where('credential_id', $pending['id'])->pluck('event')->all();
    $keys = app(AsymmetricVerificationKeys::class)->for($pending['scope']);
    $payload = 'reel-session-grant-bytes';
    openssl_sign($payload, $signature, $key['private'], OPENSSL_ALGO_SHA256);

    expect($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($credential->status)->toBe(CredentialStatus::Active)
        ->and($credential->public_key)->toBe($key['public'])
        ->and($token->consumed_at)->not->toBeNull()
        ->and($events)->toBe([
            LifecycleEventType::Issued,
            LifecycleEventType::Exchanged,
            LifecycleEventType::Activated,
        ])
        ->and($keys)->toHaveCount(1)
        ->and($keys[0])->toBeInstanceOf(AsymmetricVerificationKey::class)
        ->and($keys[0]->credentialId)->toBe($pending['id'])
        ->and($keys[0]->algorithm)->toBe(CredentialAlgorithm::Rs256)
        ->and(openssl_verify($payload, $signature, $keys[0]->publicKey, OPENSSL_ALGO_SHA256))->toBe(1)
        ->and((string) $response->getContent())->not->toContain('PUBLIC KEY', $pending['code'], 'PRIVATE KEY')
        ->and(json_encode(CredentialAuditEvent::query()->get()->toArray()))->not->toContain('PUBLIC KEY', 'PRIVATE KEY', $pending['code']);
    Log::shouldNotHaveReceived('warning');
});

it('fails closed with the default resolver and rejects caller-authored scope or private material before mutation', function (): void {
    $pending = pendingBoundEnrollment();
    $key = testsRsaKey();

    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $key['public'],
    ])->assertNotFound()->assertExactJson(['message' => 'This asymmetric enrollment is unavailable.']);

    bindEnrollmentScope($pending['scope']);
    openssl_pkey_export($key['private'], $privatePem);
    openssl_pkey_export($key['private'], $encryptedPrivatePem, 'test-only-passphrase');
    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $privatePem,
        'audience' => 'https://attacker.example',
    ])->assertUnprocessable();
    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $privatePem,
    ])->assertUnprocessable();
    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $encryptedPrivatePem,
    ])->assertUnprocessable();

    expect(Credential::query()->findOrFail($pending['id'])->public_key)->toBeNull()
        ->and(OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole()->consumed_at)->toBeNull();
});

it('makes replay substitution and every exact-scope mismatch indistinguishable without consuming the code', function (): void {
    $dimensions = [
        'appPurpose' => fn (BoundCredentialScope $scope) => new BoundCredentialScope('matte.callback', $scope->subject, $scope->installation, $scope->application, $scope->audience),
        'subject' => fn (BoundCredentialScope $scope) => new BoundCredentialScope($scope->appPurpose, new Subject($scope->subject->type, 'other-subject'), $scope->installation, $scope->application, $scope->audience),
        'installation' => fn (BoundCredentialScope $scope) => new BoundCredentialScope($scope->appPurpose, $scope->subject, 'other-install', $scope->application, $scope->audience),
        'application' => fn (BoundCredentialScope $scope) => new BoundCredentialScope($scope->appPurpose, $scope->subject, $scope->installation, 'other-app', $scope->audience),
        'audience' => fn (BoundCredentialScope $scope) => new BoundCredentialScope($scope->appPurpose, $scope->subject, $scope->installation, $scope->application, 'https://other.example'),
    ];

    foreach ($dimensions as $change) {
        $pending = pendingBoundEnrollment();
        $key = new Rs256PublicKey(testsRsaKey()['public']);
        expect(fn () => app(CompleteAsymmetricEnrollment::class)(
            $pending['code'],
            $change($pending['scope']),
            $key,
        ))->toThrow(AsymmetricEnrollmentUnavailable::class, 'unavailable');
        expect(OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole()->consumed_at)->toBeNull();
    }

    $pending = pendingBoundEnrollment();
    bindEnrollmentScope($pending['scope']);
    $first = testsRsaKey();
    $second = testsRsaKey();
    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $first['public'],
    ])->assertCreated();
    $this->postJson('/bfc/asymmetric-enrollments/'.$pending['scope']->application, [
        'enrollment_code' => $pending['code'],
        'public_key' => $second['public'],
    ])->assertNotFound();

    expect(Credential::query()->findOrFail($pending['id'])->public_key)->toBe($first['public']);
});

it('refuses every dead or malformed linked state without a partial write', function (string $case): void {
    $pending = pendingBoundEnrollment();
    $key = new Rs256PublicKey(testsRsaKey()['public']);
    match ($case) {
        'expired code' => DB::table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->update(['expires_at' => now()->subSecond()]),
        'revoked credential' => DB::table('credentials')->where('id', $pending['id'])->update(['revoked_at' => now()]),
        'expired credential' => DB::table('credentials')->where('id', $pending['id'])->update(['expires_at' => now()->subSecond()]),
        'already active' => DB::table('credentials')->where('id', $pending['id'])->update(['status' => 'active']),
        'wrong kind' => DB::table('credentials')->where('id', $pending['id'])->update(['kind' => 'bearer']),
        'wrong purpose' => DB::table('credentials')->where('id', $pending['id'])->update(['purpose' => 'enrollment']),
        'wrong ownership' => (function () use ($pending): void {
            $user = User::query()->create([
                'name' => 'Wrong enrollment owner',
                'email' => 'wrong-enrollment-owner@example.test',
                'password' => bcrypt('test-created-password'),
            ]);
            DB::table('credentials')->where('id', $pending['id'])->update(['user_id' => $user->getKey()]);
        })(),
        'malformed binding hash' => DB::table('credential_protocol_bindings')->where('credential_id', $pending['id'])->update(['scope_hash' => str_repeat('0', 64)]),
        'wrong binding algorithm' => DB::table('credential_protocol_bindings')->where('credential_id', $pending['id'])->update(['algorithm' => 'hmac-sha256']),
        'wrong binding role' => DB::table('credential_protocol_bindings')->where('credential_id', $pending['id'])->update(['material_role' => 'verification_copy']),
        'unlinked' => DB::table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->update(['durable_credential_id' => null]),
    };
    $before = [
        DB::table('credentials')->where('id', $pending['id'])->first(),
        DB::table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->first(),
        CredentialAuditEvent::query()->count(),
        CredentialOutboxEntry::query()->count(),
    ];

    expect(fn () => app(CompleteAsymmetricEnrollment::class)($pending['code'], $pending['scope'], $key))
        ->toThrow(AsymmetricEnrollmentUnavailable::class);
    expect([
        DB::table('credentials')->where('id', $pending['id'])->first(),
        DB::table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->first(),
        CredentialAuditEvent::query()->count(),
        CredentialOutboxEntry::query()->count(),
    ])->toEqual($before);
})->with([
    'expired code',
    'revoked credential',
    'expired credential',
    'already active',
    'wrong kind',
    'wrong purpose',
    'wrong ownership',
    'malformed binding hash',
    'wrong binding algorithm',
    'wrong binding role',
    'unlinked',
]);

it('rejects malformed and non-closed HTTP objects without resolver or storage work', function (): void {
    $pending = pendingBoundEnrollment();
    $called = false;
    app()->instance(ResolvesAsymmetricEnrollmentScope::class, new class($called) implements ResolvesAsymmetricEnrollmentScope
    {
        public function __construct(private bool &$called) {}

        public function resolve(Request $request, string $application): ?BoundCredentialScope
        {
            $this->called = true;

            return null;
        }
    });

    $cases = [
        [],
        ['enrollment_code' => str_repeat('a', 64)],
        ['enrollment_code' => str_repeat('a', 64), 'public_key' => []],
        ['enrollment_code' => [], 'public_key' => 'key'],
        ['enrollment_code' => 'not-a-code', 'public_key' => 'key'],
        ['enrollment_code' => str_repeat('a', 64), 'public_key' => 'key', 'algorithm' => 'RS256'],
    ];

    foreach ($cases as $case) {
        $this->postJson('/bfc/asymmetric-enrollments/app_1', $case)->assertUnprocessable();
    }

    $this->call('POST', '/bfc/asymmetric-enrollments/app_1', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
    ], '{')->assertUnprocessable();

    expect($called)->toBeFalse()
        ->and(Credential::query()->findOrFail($pending['id'])->public_key)->toBeNull();
});

it('rolls back key activation code consumption and audit when lifecycle recording fails', function (): void {
    $pending = pendingBoundEnrollment();
    DB::unprepared(<<<'SQL'
        CREATE TRIGGER fail_asymmetric_audit
        BEFORE INSERT ON credential_audit_events
        WHEN NEW.event = 'exchanged'
        BEGIN
            SELECT RAISE(ABORT, 'forced audit failure');
        END
        SQL);

    try {
        app(CompleteAsymmetricEnrollment::class)(
            $pending['code'],
            $pending['scope'],
            new Rs256PublicKey(testsRsaKey()['public']),
        );
        test()->fail('The forced audit failure unexpectedly committed.');
    } catch (Throwable) {
        // Expected: the assertion below proves every state write rolled back.
    } finally {
        DB::unprepared('DROP TRIGGER fail_asymmetric_audit');
    }

    expect(Credential::query()->findOrFail($pending['id'])->status)->toBe(CredentialStatus::Pending)
        ->and(Credential::query()->findOrFail($pending['id'])->public_key)->toBeNull()
        ->and(OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole()->consumed_at)->toBeNull()
        ->and(CredentialAuditEvent::query()->where('credential_id', $pending['id'])->count())->toBe(1);
});

it('accepts only canonicalizable RSA SPKI material within the fixed size range', function (): void {
    $rsa = testsRsaKey();
    $canonical = new Rs256PublicKey($rsa['public']);
    $transport = new Rs256PublicKey(" \r\n".str_replace("\n", "\r\n", $rsa['public'])." \t");
    $rsa4096 = testsRsaKey(4096);
    $tooSmall = testsRsaKey(1024);
    $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $ecDetails = openssl_pkey_get_details($ec);
    $csr = openssl_csr_new(['commonName' => 'bfc.test'], $rsa['private']);
    $certificate = openssl_csr_sign($csr, null, $rsa['private'], 1);
    openssl_x509_export($certificate, $certificatePem);
    openssl_pkey_export($rsa['private'], $privatePem);
    $rsaDetails = openssl_pkey_get_details($rsa['private']);
    $pkcs1 = testsPkcs1PublicKey($rsaDetails['rsa']['n'], $rsaDetails['rsa']['e']);

    expect($canonical->pem)->toBe($rsa['public'])
        ->and($transport->pem)->toBe($rsa['public'])
        ->and((new Rs256PublicKey($rsa4096['public']))->pem)->toBe($rsa4096['public']);

    foreach ([
        $tooSmall['public'],
        $ecDetails['key'],
        $certificatePem,
        $privatePem,
        $pkcs1,
        file_get_contents(__DIR__.'/Fixtures/ed25519-public.pem'),
        file_get_contents(__DIR__.'/Fixtures/rsa-9216-public.pem'),
        $rsa['public'].$rsa4096['public'],
        $rsa['public'].'payload',
        "-----BEGIN PUBLIC KEY-----\nnot-base64!\n-----END PUBLIC KEY-----\n",
        '/tmp/key.pem',
        'file:///tmp/key.pem',
        'https://example.test/key.pem',
    ] as $refused) {
        expect(fn () => new Rs256PublicKey($refused))->toThrow(InvalidCredentialInput::class);
    }
});

it('rejects oversized HTTP bodies and key values before OpenSSL or resolver work', function (): void {
    $called = false;
    app()->instance(ResolvesAsymmetricEnrollmentScope::class, new class($called) implements ResolvesAsymmetricEnrollmentScope
    {
        public function __construct(private bool &$called) {}

        public function resolve(Request $request, string $application): ?BoundCredentialScope
        {
            $this->called = true;

            return null;
        }
    });

    $this->call('POST', '/bfc/asymmetric-enrollments/app', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
    ], str_repeat('x', 24577))->assertUnprocessable();
    $this->postJson('/bfc/asymmetric-enrollments/app', [
        'enrollment_code' => str_repeat('a', 64),
        'public_key' => str_repeat('x', 16385),
    ])->assertUnprocessable();

    expect($called)->toBeFalse();
});

it('selects exact canonical keys in frozen order and ignores hash collisions and legacy rows', function (): void {
    $first = pendingBoundEnrollment();
    $second = pendingBoundEnrollment();
    $firstKey = testsRsaKey();
    $secondKey = testsRsaKey();
    app(CompleteAsymmetricEnrollment::class)($first['code'], $first['scope'], new Rs256PublicKey($firstKey['public']));
    $this->travel(1)->seconds();
    app(CompleteAsymmetricEnrollment::class)($second['code'], $second['scope'], new Rs256PublicKey($secondKey['public']));

    $legacy = Credential::factory()->asymmetric()->create([
        'subject_type' => $first['scope']->subject->type,
        'subject_ref' => $first['scope']->subject->ref,
        'public_key' => $firstKey['public'],
    ]);
    DB::table('credential_protocol_bindings')->where('credential_id', $first['id'])->update([
        'application_ref' => 'collision-app',
    ]);
    $keys = app(AsymmetricVerificationKeys::class)->for($first['scope']);

    expect(array_column($keys, 'credentialId'))->toBe([$second['id']])
        ->and(Credential::activePublicKeysFor($legacy->subject_type, $legacy->subject_ref))->toBe([$legacy->public_key]);
});

it('excludes every wrong lookup dimension lifecycle and malformed stored shape', function (): void {
    $pending = pendingBoundEnrollment();
    $key = testsRsaKey();
    app(CompleteAsymmetricEnrollment::class)($pending['code'], $pending['scope'], new Rs256PublicKey($key['public']));
    $lookup = app(AsymmetricVerificationKeys::class);

    foreach ([
        new BoundCredentialScope('matte.callback', $pending['scope']->subject, $pending['scope']->installation, $pending['scope']->application, $pending['scope']->audience),
        new BoundCredentialScope($pending['scope']->appPurpose, new Subject(SubjectType::Installation, 'wrong-subject'), $pending['scope']->installation, $pending['scope']->application, $pending['scope']->audience),
        new BoundCredentialScope($pending['scope']->appPurpose, $pending['scope']->subject, 'wrong-installation', $pending['scope']->application, $pending['scope']->audience),
        new BoundCredentialScope($pending['scope']->appPurpose, $pending['scope']->subject, $pending['scope']->installation, 'wrong-application', $pending['scope']->audience),
        new BoundCredentialScope($pending['scope']->appPurpose, $pending['scope']->subject, $pending['scope']->installation, $pending['scope']->application, 'https://wrong.example'),
    ] as $wrongScope) {
        expect($lookup->for($wrongScope))->toBe([]);
    }

    $credential = DB::table('credentials')->where('id', $pending['id'])->first();
    $binding = DB::table('credential_protocol_bindings')->where('credential_id', $pending['id'])->first();
    $wrongOwner = User::query()->create([
        'name' => 'Wrong lookup owner',
        'email' => 'wrong-lookup-owner@example.test',
        'password' => bcrypt('test-created-password'),
    ]);
    $mutations = [
        ['credentials', ['status' => 'pending']],
        ['credentials', ['revoked_at' => now()]],
        ['credentials', ['expires_at' => now()->subSecond()]],
        ['credentials', ['kind' => 'bearer']],
        ['credentials', ['purpose' => 'enrollment']],
        ['credentials', ['public_key' => null]],
        ['credentials', ['public_key' => " \n".$key['public']]],
        ['credentials', ['subject_ref' => 'wrong-subject']],
        ['credentials', ['user_id' => $wrongOwner->getKey()]],
        ['credential_protocol_bindings', ['app_purpose' => 'matte.callback']],
        ['credential_protocol_bindings', ['installation_ref' => 'wrong-installation']],
        ['credential_protocol_bindings', ['application_ref' => 'wrong-application']],
        ['credential_protocol_bindings', ['audience' => 'https://wrong.example']],
        ['credential_protocol_bindings', ['algorithm' => 'hmac-sha256']],
        ['credential_protocol_bindings', ['material_role' => 'verification_copy']],
        ['credential_protocol_bindings', ['scope_hash' => str_repeat('0', 64)]],
    ];

    foreach ($mutations as [$table, $change]) {
        $keyColumn = $table === 'credentials' ? 'id' : 'credential_id';
        DB::table($table)->where($keyColumn, $pending['id'])->update($change);
        expect($lookup->for($pending['scope']))->toBe([]);
        $original = $table === 'credentials' ? (array) $credential : (array) $binding;
        DB::table($table)->where($keyColumn, $pending['id'])->update(array_intersect_key($original, $change));
    }
});

it('defers bound grace until enrollment then returns overlap in order and only the replacement after grace', function (): void {
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00'));
    $source = pendingBoundEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $rotation = app(RotateCredential::class)($source['id'], new RotateOptions(codeTtlSeconds: 3600));
    $replacementId = $rotation?->mint->summary->id;
    $replacementCode = $rotation?->mint->secret?->reveal();

    expect(Credential::query()->findOrFail($source['id'])->expires_at)->toBeNull();
    expect(fn () => app(RotateCredential::class)($source['id'], new RotateOptions))
        ->toThrow(RotationRefused::class, 'PENDING public-key enrollment');
    expect(Credential::query()->findOrFail($source['id'])->expires_at)->toBeNull();

    app(CompleteAsymmetricEnrollment::class)(
        (string) $replacementCode,
        $source['scope'],
        new Rs256PublicKey(testsRsaKey()['public']),
    );
    $old = Credential::query()->findOrFail($source['id']);
    $keys = app(AsymmetricVerificationKeys::class)->for($source['scope']);

    expect($old->expires_at?->equalTo(now()->addHour()))->toBeTrue()
        ->and(array_column($keys, 'credentialId'))->toBe([$replacementId, $source['id']]);

    $this->travelTo(now()->addHour());
    expect(array_column(app(AsymmetricVerificationKeys::class)->for($source['scope']), 'credentialId'))
        ->toBe([$replacementId]);
});

it('makes emergency bound rotation an explicit outage until enrollment', function (): void {
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00'));
    $source = pendingBoundEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $rotation = app(RotateCredential::class)(
        $source['id'],
        new RotateOptions(emergency: true, codeTtlSeconds: 3600),
    );
    $replacementId = (string) $rotation?->mint->summary->id;

    expect(Credential::query()->findOrFail($source['id'])->expires_at?->lessThanOrEqualTo(now()))->toBeTrue()
        ->and(app(AsymmetricVerificationKeys::class)->for($source['scope']))->toBe([]);

    app(CompleteAsymmetricEnrollment::class)(
        (string) $rotation?->mint->secret?->reveal(),
        $source['scope'],
        new Rs256PublicKey(testsRsaKey()['public']),
    );

    expect(array_column(app(AsymmetricVerificationKeys::class)->for($source['scope']), 'credentialId'))
        ->toBe([$replacementId]);
});

it('rolls back replacement activation and predecessor cutover together', function (): void {
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00'));
    $source = pendingBoundEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $rotation = app(RotateCredential::class)($source['id'], new RotateOptions(codeTtlSeconds: 3600));
    $replacementId = (string) $rotation?->mint->summary->id;
    $replacementCode = (string) $rotation?->mint->secret?->reveal();
    DB::unprepared(<<<'SQL'
        CREATE TRIGGER fail_asymmetric_cutover_audit
        BEFORE INSERT ON credential_audit_events
        WHEN NEW.event = 'rotated' AND NEW.reason_code = 'cutover_completion'
        BEGIN
            SELECT RAISE(ABORT, 'forced cutover audit failure');
        END
        SQL);

    try {
        app(CompleteAsymmetricEnrollment::class)(
            $replacementCode,
            $source['scope'],
            new Rs256PublicKey(testsRsaKey()['public']),
        );
        test()->fail('The forced cutover audit failure unexpectedly committed.');
    } catch (Throwable) {
        // The state assertions below prove the transition rolled back as one unit.
    } finally {
        DB::unprepared('DROP TRIGGER fail_asymmetric_cutover_audit');
    }

    expect(Credential::query()->findOrFail($source['id'])->expires_at)->toBeNull()
        ->and(Credential::query()->findOrFail($replacementId)->status)->toBe(CredentialStatus::Pending)
        ->and(Credential::query()->findOrFail($replacementId)->public_key)->toBeNull()
        ->and(OnboardingToken::query()->where('durable_credential_id', $replacementId)->sole()->consumed_at)->toBeNull()
        ->and(CredentialAuditEvent::query()->where('credential_id', $replacementId)->where('event', LifecycleEventType::Activated)->exists())->toBeFalse();
});

it('reissues one lost bound delivery without redelivery or same-second lineage ambiguity', function (): void {
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00'));
    $source = pendingBoundEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $first = app(RotateCredential::class)($source['id'], new RotateOptions(codeTtlSeconds: 3600));
    $firstId = $first?->mint->summary->id;
    $firstCode = $first?->mint->secret?->reveal();
    $reissued = app(RotateCredential::class)(
        $source['id'],
        new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true),
    );

    expect(Credential::query()->findOrFail((string) $firstId)->revoked_at)->not->toBeNull()
        ->and(OnboardingToken::query()->where('durable_credential_id', $firstId)->sole()->consumed_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()->where('credential_id', $firstId)->where('reason_code', AuditReason::DeliveryAbandoned)->exists())->toBeTrue()
        ->and($reissued?->mint->summary->id)->not->toBe($firstId)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $reissued?->mint->summary->id)
            ->where('event', LifecycleEventType::Issued)
            ->whereNotNull('code_id')
            ->exists())->toBeTrue()
        ->and(Credential::query()->where('status', CredentialStatus::Pending)->whereNull('revoked_at')->count())->toBe(1);

    expect(fn () => app(CompleteAsymmetricEnrollment::class)(
        (string) $firstCode,
        $source['scope'],
        new Rs256PublicKey(testsRsaKey()['public']),
    ))->toThrow(AsymmetricEnrollmentUnavailable::class);

    $before = Credential::query()->count();
    expect(fn () => app(RotateCredential::class)(
        $source['id'],
        new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true),
    ))->toThrow(RotationRefused::class, 'unavailable');
    expect(Credential::query()->count())->toBe($before);
});

it('carries bound delivery reissue through both HTTP and CLI transports without replay issuance', function (string $transport): void {
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00'));
    $source = pendingBoundEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $first = app(RotateCredential::class)($source['id'], new RotateOptions(codeTtlSeconds: 3600));
    $firstId = (string) $first?->mint->summary->id;
    $headers = $transport === 'http' ? asymmetricRotationHeaders() : [];
    $before = Credential::query()->count();

    if ($transport === 'http') {
        $this->postJson('/bfc/credentials/'.$source['id'].'/rotate', [
            'reissue_pending_delivery' => true,
            'code_ttl_seconds' => 3600,
        ], $headers)->assertCreated()
            ->assertJsonPath('superseded_id', $source['id'])
            ->assertJsonPath('delivery.shape', 'enrollment_code');
    } else {
        expect(Artisan::call('bfc:credential:rotate', [
            'id' => $source['id'],
            '--reissue-pending-delivery' => true,
            '--code-ttl' => '3600',
            '--local' => true,
        ]))->toBe(0);
    }

    expect(Credential::query()->count())->toBe($before + 1)
        ->and(Credential::query()->findOrFail($firstId)->revoked_at)->not->toBeNull();
    $after = Credential::query()->count();

    if ($transport === 'http') {
        $this->postJson('/bfc/credentials/'.$source['id'].'/rotate', [
            'reissue_pending_delivery' => true,
            'code_ttl_seconds' => 3600,
        ], $headers)->assertStatus(409);
    } else {
        expect(Artisan::call('bfc:credential:rotate', [
            'id' => $source['id'],
            '--reissue-pending-delivery' => true,
            '--code-ttl' => '3600',
            '--local' => true,
        ]))->toBe(1);
    }

    expect(Credential::query()->count())->toBe($after);
})->with(['http', 'cli']);

it('keeps bound asymmetric codes out of both legacy exchange surfaces before burn', function (): void {
    $pending = pendingBoundEnrollment();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $pending['code']])->assertBadRequest();
    $this->postJson('/bfc/claim', ['version' => 1, 'claim_code' => $pending['code']])->assertBadRequest();

    expect(OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole()->consumed_at)->toBeNull()
        ->and(Credential::query()->findOrFail($pending['id'])->revoked_at)->toBeNull();
});
