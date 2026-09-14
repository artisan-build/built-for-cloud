<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialManagementScope;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

function signingRoot(): Credential
{
    app(SigningRootLifecycle::class)->provision();

    /** @var Credential */
    return Credential::query()->where('purpose', CredentialPurpose::SigningRoot->value)->firstOrFail();
}

it('provisions exactly one direct-active root through the local-only framed command without exporting material', function (): void {
    expect(Artisan::call('bfc:signing-root:provision'))->toBe(1)
        ->and(Artisan::output())->toContain('local-only')
        ->and(Credential::query()->count())->toBe(0);

    expect(Artisan::call('bfc:signing-root:provision', ['--local' => true]))->toBe(0);

    $output = Artisan::output();
    /** @var Credential $root */
    $root = Credential::query()->firstOrFail();

    expect($root->kind)->toBe(CredentialKind::Hmac)
        ->and($root->purpose)->toBe(CredentialPurpose::SigningRoot)
        ->and($root->subject_type)->toBe(SubjectType::Installation)
        ->and($root->subject_ref)->toBe(SigningRootMac::SUBJECT_REF)
        ->and($root->abilities)->toBeNull()
        ->and($root->status)->toBe(CredentialStatus::Active)
        ->and($root->revoked_at)->toBeNull()
        ->and($root->rotated_at)->toBeNull()
        ->and($root->expires_at)->toBeNull()
        ->and($root->delivered_at)->toBeNull()
        ->and($root->delivery_fingerprint)->toBeNull()
        ->and($output)->toContain($root->id, 'No secret was exported.')
        ->and($output)->not->toContain((string) $root->secret_ciphertext)
        ->and(app(ListCredentials::class)())->toBe([])
        ->and(app(ListCredentials::class)(managementScope: CredentialManagementScope::memberInstallation()))->toBe([]);

    expect(Artisan::call('bfc:signing-root:provision', ['--local' => true]))->toBe(1)
        ->and(Credential::query()->count())->toBe(1);
});

it('MACs opaque bytes with the sole current root and exposes only its id and lowercase HMAC-SHA256', function (): void {
    $root = signingRoot();
    $bytes = "opaque\0bytes\n{not-json}";
    $result = app(SigningRootMac::class)->mac($bytes);
    $plaintext = app(HmacKeyring::class)->decrypt((string) $root->secret_ciphertext, $root->secret_key_version);

    expect(array_keys(get_object_vars($result)))->toBe(['keyId', 'lowercaseHexMac'])
        ->and($result->keyId)->toBe($root->id)
        ->and($result->lowercaseHexMac)->toBe(hash_hmac('sha256', $bytes, $plaintext))
        ->and($result->lowercaseHexMac)->toMatch('/^[0-9a-f]{64}$/')
        ->and(app(SigningRootMac::class)->verify($root->id, $bytes, $result->lowercaseHexMac))->toBeTrue()
        ->and(app(SigningRootMac::class)->verify($root->id, $bytes.'changed', $result->lowercaseHexMac))->toBeFalse()
        ->and(app(SigningRootMac::class)->verify((string) Str::uuid(), $bytes, $result->lowercaseHexMac))->toBeFalse()
        ->and(app(SigningRootMac::class)->verify($root->id, $bytes, strtoupper($result->lowercaseHexMac)))->toBeFalse()
        ->and(app(SigningRootMac::class)->verify($root->id, $bytes, 'not-a-mac'))->toBeFalse();
});

it('keeps root material out of action summary list HTTP CLI and audit surfaces', function (): void {
    $result = app(SigningRootLifecycle::class)->provision();
    /** @var Credential $root */
    $root = Credential::query()->findOrFail($result->summary->id);
    $plaintext = app(HmacKeyring::class)->decrypt((string) $root->secret_ciphertext, $root->secret_key_version);
    $mac = $this->assertNoSecretLeakage(
        $plaintext,
        fn () => app(SigningRootMac::class)->mac('disclosure inventory bytes'),
    );

    expect($result->delivery)->toBe(DeliveryShape::None)
        ->and($result->secret)->toBeNull()
        ->and($result->deliveryFingerprint)->toBeNull()
        ->and(array_keys($result->summary->toArray()))->toBe([
            'id', 'kind', 'purpose', 'subject_type', 'subject_ref', 'name', 'abilities', 'status',
            'created_at', 'last_used_at', 'expires_at', 'revoked_at', 'rotated_at',
            'presentation_cadence_seconds', 'unsupported',
        ])
        ->and(serialize($result->summary->toArray()))->not->toContain(
            $plaintext,
            (string) $root->secret_ciphertext,
            $mac->lowercaseHexMac,
        );

    expect(Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]))->toBe(0);
    $cli = Artisan::output();

    expect(json_decode($cli, true, flags: JSON_THROW_ON_ERROR))->toBe([])
        ->and($cli)->not->toContain($root->id, $plaintext, (string) $root->secret_ciphertext, $mac->lowercaseHexMac);
    $this->assertConsoleOutputCarriesNoSecret($cli, $plaintext);

    $http = $this->getJson('/bfc/credentials', [
        'Authorization' => 'Bearer '.auditOperatorCredential('root-disclosure-operator'),
    ])->assertOk();
    $this->assertResponseCarriesNoSecret($http, $plaintext);
    expect($http->getContent())->not->toContain($root->id, (string) $root->secret_ciphertext, $mac->lowercaseHexMac);

    $audit = CredentialAuditEvent::query()
        ->where('credential_id', $root->id)
        ->get()
        ->map(static fn (CredentialAuditEvent $event): array => $event->getAttributes())
        ->all();

    expect($audit)->toHaveCount(1)
        ->and($audit[0]['note'])->toBeNull()
        ->and(serialize($audit))->not->toContain($plaintext, (string) $root->secret_ciphertext, $mac->lowercaseHexMac);
});

it('delegates unchanged public rotation to direct-active make-before-break and verifies the old id only through grace', function (): void {
    $old = signingRoot();
    $bytes = 'signed before rotation';
    $oldMac = app(SigningRootMac::class)->mac($bytes);

    $result = app(RotateCredential::class)($old->id, new RotateOptions);

    expect($result)->not->toBeNull()
        ->and($result->mint->delivery)->toBe(DeliveryShape::None)
        ->and($result->mint->secret)->toBeNull()
        ->and($result->mint->summary->status)->toBe('active')
        ->and($result->supersededId)->toBe($old->id);

    $old->refresh();
    $newMac = app(SigningRootMac::class)->mac($bytes);

    expect($newMac->keyId)->toBe($result->mint->summary->id)
        ->and($newMac->keyId)->not->toBe($old->id)
        ->and($old->rotated_at)->not->toBeNull()
        ->and($old->expires_at?->diffInSeconds(now()->addHour(), true))->toBeLessThan(1.0)
        ->and(app(SigningRootMac::class)->verify($old->id, $bytes, $oldMac->lowercaseHexMac))->toBeTrue()
        ->and(app(SigningRootMac::class)->verify($newMac->keyId, $bytes, $newMac->lowercaseHexMac))->toBeTrue();

    $this->travel(3600)->seconds();

    expect(app(SigningRootMac::class)->verify($old->id, $bytes, $oldMac->lowercaseHexMac))->toBeFalse()
        ->and(app(SigningRootMac::class)->verify($newMac->keyId, $bytes, $newMac->lowercaseHexMac))->toBeTrue();
});

it('ends old verification at an emergency rotation cutover', function (): void {
    $old = signingRoot();
    $oldMac = app(SigningRootMac::class)->mac('emergency bytes');

    $result = app(RotateCredential::class)($old->id, new RotateOptions(emergency: true));

    expect($result)->not->toBeNull()
        ->and(app(SigningRootMac::class)->verify($old->id, 'emergency bytes', $oldMac->lowercaseHexMac))->toBeFalse()
        ->and($old->refresh()->expires_at?->diffInSeconds(now(), true))->toBeLessThan(1.0)
        ->and(app(SigningRootMac::class)->mac('emergency bytes')->keyId)->toBe($result->mint->summary->id);
});

it('refuses generic root mutations and option-changing rotation before committing an ordinary path', function (RotateOptions $options): void {
    $root = signingRoot();
    $before = $root->getAttributes();

    expect(fn () => app(RotateCredential::class)($root->id, $options))
        ->toThrow(CredentialVerbRefused::class)
        ->and(Credential::query()->count())->toBe(1)
        ->and($root->refresh()->getAttributes())->toBe($before);
})->with([
    'abilities' => fn (): RotateOptions => new RotateOptions(abilitiesProvided: true, abilities: []),
    'expiry' => fn (): RotateOptions => new RotateOptions(expiryProvided: true, expiresAt: now()->addDay()),
    'code ttl' => fn (): RotateOptions => new RotateOptions(codeTtlSeconds: 3600),
    'override' => fn (): RotateOptions => new RotateOptions(override: true),
]);

it('refuses generic mint activation revoke and offboarding for the reserved root identity', function (): void {
    $root = signingRoot();

    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Installation, SigningRootMac::SUBJECT_REF),
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::SigningRoot),
    ))->toThrow(CredentialVerbRefused::class)
        ->and(fn () => app(ActivateCredential::class)($root->id, 'irrelevant'))
        ->toThrow(CredentialVerbRefused::class)
        ->and(fn () => app(RevokeCredential::class)($root->id))
        ->toThrow(CredentialVerbRefused::class)
        ->and(fn () => app(OffboardSubject::class)(OffboardOptions::fromInput([
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => SigningRootMac::SUBJECT_REF,
        ])))->toThrow(CredentialVerbRefused::class)
        ->and($root->refresh()->revoked_at)->toBeNull();
});

it('keeps installation-management mutation scopes from selecting the reserved root', function (): void {
    $root = signingRoot();
    $before = $root->getAttributes();
    $scope = CredentialManagementScope::memberInstallation();

    expect(app(RotateCredential::class)($root->id, new RotateOptions, managementScope: $scope))->toBeNull()
        ->and(app(RevokeCredential::class)($root->id, managementScope: $scope))->toBe(RevokeOutcome::NotFound)
        ->and($root->refresh()->getAttributes())->toBe($before)
        ->and(Credential::query()->count())->toBe(1);
});

it('refuses a claim link to root material before burning the code or decrypting the row', function (): void {
    $root = signingRoot();
    $plaintextCode = 'root-link-'.bin2hex(random_bytes(16));

    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => null,
        'scope' => Scope::Onboard->value,
        'token_hash' => OnboardingToken::hashToken($plaintextCode),
        'durable_credential_id' => $root->id,
        'expires_at' => now()->addHour(),
    ]);

    $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $plaintextCode]);

    $response->assertStatus(400)->assertJsonPath('error', 'invalid_code');
    expect($code->refresh()->consumed_at)->toBeNull()
        ->and($root->refresh()->getRawOriginal('secret_ciphertext'))->not->toBeNull();
});

it('fails closed on zero multiple foreign and invalid current-root states without adding a replacement', function (): void {
    $root = signingRoot();
    $encrypted = app(HmacKeyring::class)->encrypt(bin2hex(random_bytes(32)));

    DB::table('credentials')->insert([
        'id' => (string) Str::uuid(),
        'kind' => CredentialKind::Hmac->value,
        'purpose' => CredentialPurpose::SigningRoot->value,
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'foreign-root',
        'abilities' => null,
        'status' => CredentialStatus::Active->value,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(fn () => app(SigningRootMac::class)->mac('bytes'))->toThrow(SigningRootRefused::class)
        ->and(fn () => app(SigningRootLifecycle::class)->rotate($root->id, false))->toThrow(SigningRootRefused::class)
        ->and(Credential::query()->count())->toBe(2);

    DB::table('credentials')->where('id', '!=', $root->id)->delete();
    Credential::query()->whereKey($root->id)->update(['expires_at' => now()]);

    expect(fn () => app(SigningRootLifecycle::class)->rotate($root->id, false))->toThrow(SigningRootRefused::class)
        ->and(Credential::query()->count())->toBe(1);
});

it('selects purpose kind subject lifecycle and key version before any successful root result', function (string $column, mixed $value): void {
    $root = signingRoot();
    $mac = app(SigningRootMac::class)->mac('ordered selection');

    DB::table('credentials')->where('id', $root->id)->update([$column => $value]);

    expect(fn () => app(SigningRootMac::class)->mac('ordered selection'))->toThrow(SigningRootRefused::class)
        ->and(app(SigningRootMac::class)->verify($root->id, 'ordered selection', $mac->lowercaseHexMac))->toBeFalse();
})->with([
    'wrong purpose' => ['purpose', CredentialPurpose::Signing->value],
    'wrong kind' => ['kind', CredentialKind::Bearer->value],
    'wrong subject' => ['subject_ref', 'another-installation'],
    'revoked' => ['revoked_at', '2000-01-01 00:00:00'],
    'expired' => ['expires_at', '2000-01-01 00:00:00'],
    'non-active' => ['status', CredentialStatus::Pending->value],
]);

it('refuses an unavailable root key version without returning a MAC', function (): void {
    $root = signingRoot();
    $mac = app(SigningRootMac::class)->mac('unavailable version');
    DB::table('credentials')->where('id', $root->id)->update(['secret_key_version' => 'unavailable0000']);

    expect(fn () => app(SigningRootMac::class)->mac('unavailable version'))
        ->toThrow(HmacKeyUnreadable::class)
        ->and(app(SigningRootMac::class)->verify($root->id, 'unavailable version', $mac->lowercaseHexMac))->toBeFalse();
});
