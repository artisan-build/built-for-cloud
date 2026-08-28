<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('stores rows of every credential kind without schema alteration', function (): void {
    foreach ([CredentialKind::Bearer, CredentialKind::Basic] as $kind) {
        $credential = Credential::query()->create([
            'kind' => $kind,
            'subject_type' => SubjectType::Application,
            'subject_ref' => 'app-'.$kind->value,
            'secret_hash' => hash('sha256', 'secret-'.$kind->value),
        ]);

        expect($credential->exists)->toBeTrue()
            ->and($credential->refresh()->kind)->toBe($kind);
    }

    // hmac's at-rest shape is ciphertext + key-version, never a hash
    // (PRD 1.21 / D9.1 — this PR defines the kind the stub reserved).
    $hmac = Credential::factory()->hmac()->create(['subject_ref' => 'app-hmac']);

    expect($hmac->refresh()->kind)->toBe(CredentialKind::Hmac);

    $asymmetric = Credential::query()->create([
        'kind' => CredentialKind::Asymmetric,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
        'public_key' => CredentialFactory::generatePublicKey(),
    ]);

    expect($asymmetric->refresh()->kind)->toBe(CredentialKind::Asymmetric);
});

it('stores rows for every subject type', function (): void {
    foreach (SubjectType::cases() as $type) {
        $credential = Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'subject_type' => $type,
            'subject_ref' => 'ref-'.$type->value,
            'secret_hash' => hash('sha256', 'secret-'.$type->value),
        ]);

        expect($credential->refresh()->subject_type)->toBe($type);
    }
});

it('refuses to persist secret material on an asymmetric credential', function (): void {
    expect(fn (): Credential => Credential::query()->create([
        'kind' => CredentialKind::Asymmetric,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
        'public_key' => CredentialFactory::generatePublicKey(),
        'secret_hash' => hash('sha256', 'a-private-secret'),
    ]))->toThrow(InvalidArgumentException::class);

    expect(Credential::query()->count())->toBe(0);
});

it('refuses to add secret material to an existing asymmetric credential', function (): void {
    $credential = Credential::factory()->asymmetric()->create();

    expect(function () use ($credential): void {
        $credential->secret_hash = hash('sha256', 'smuggled');
        $credential->save();
    })->toThrow(InvalidArgumentException::class);

    expect($credential->refresh()->secret_hash)->toBeNull();
});

it('persists an asymmetric credential with a real public key and a null secret hash', function (): void {
    $publicKey = CredentialFactory::generatePublicKey();

    $credential = Credential::query()->create([
        'kind' => CredentialKind::Asymmetric,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
        'public_key' => $publicKey,
    ]);

    $credential->refresh();

    expect($credential->public_key)->toBe($publicKey)
        ->and($credential->secret_hash)->toBeNull();
});

it('refuses private-key material in public_key on any kind', function (): void {
    $privatePem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";

    expect(fn (): Credential => Credential::factory()->create(['public_key' => $privatePem]))
        ->toThrow(InvalidArgumentException::class);

    expect(fn (): Credential => Credential::factory()->asymmetric($privatePem)->create())
        ->toThrow(InvalidArgumentException::class);

    // Marker detection is case-insensitive and covers encrypted keys.
    expect(fn (): Credential => Credential::factory()->create([
        'public_key' => '-----begin encrypted private key-----',
    ]))->toThrow(InvalidArgumentException::class);

    expect(Credential::query()->whereNotNull('public_key')->count())->toBe(0);
});

it('refuses a file:// url as an asymmetric public_key', function (): void {
    // openssl_pkey_get_public() would happily resolve this locator to a key;
    // the store must hold key MATERIAL, never a mutable filesystem reference.
    expect(fn (): Credential => Credential::factory()->asymmetric('file:///etc/ssl/cert.pem')->create())
        ->toThrow(InvalidArgumentException::class);

    expect(Credential::query()->count())->toBe(0);
});

it('refuses a bare filesystem path to a real pem as an asymmetric public_key', function (): void {
    $path = sys_get_temp_dir().'/bfc-test-public-'.bin2hex(random_bytes(8)).'.pem';
    file_put_contents($path, CredentialFactory::generatePublicKey());

    try {
        expect(fn (): Credential => Credential::factory()->asymmetric($path)->create())
            ->toThrow(InvalidArgumentException::class);

        expect(fn (): Credential => Credential::factory()->asymmetric('file://'.$path)->create())
            ->toThrow(InvalidArgumentException::class);

        expect(Credential::query()->count())->toBe(0);
    } finally {
        @unlink($path);
    }
});

it('refuses a public_key that does not parse on an asymmetric row', function (): void {
    expect(fn (): Credential => Credential::factory()->asymmetric('not-a-key')->create())
        ->toThrow(InvalidArgumentException::class);

    expect(fn (): Credential => Credential::factory()->asymmetric(
        "-----BEGIN PUBLIC KEY-----\n".base64_encode(random_bytes(32))."\n-----END PUBLIC KEY-----",
    )->create())->toThrow(InvalidArgumentException::class);

    expect(Credential::query()->count())->toBe(0);
});

it('has no column for private key material', function (): void {
    $columns = Schema::getColumnListing('credentials');

    foreach ($columns as $column) {
        expect(str_contains($column, 'private'))->toBeFalse();
    }

    expect($columns)->toContain('public_key');
});

it('accepts duplicate names without a unique violation', function (): void {
    $first = Credential::factory()->create(['name' => 'ci', 'subject_ref' => 'tenant-a']);
    $second = Credential::factory()->create(['name' => 'ci', 'subject_ref' => 'tenant-b']);

    expect($first->exists)->toBeTrue()
        ->and($second->exists)->toBeTrue()
        ->and(Credential::query()->where('name', 'ci')->count())->toBe(2);
});

it('treats the name as nullable and freely editable', function (): void {
    $credential = Credential::factory()->create(['name' => null]);

    expect($credential->refresh()->name)->toBeNull();

    $credential->name = 'renamed';
    $credential->save();

    expect($credential->refresh()->name)->toBe('renamed');
});

it('expresses the pending, active, revoked and expired lifecycle states', function (): void {
    $pending = Credential::factory()->pending()->create();
    $active = Credential::factory()->create();
    $revoked = Credential::factory()->revoked()->create();
    $expired = Credential::factory()->expired()->create();

    expect($pending->refresh()->status)->toBe(CredentialStatus::Pending)
        ->and($active->refresh()->status)->toBe(CredentialStatus::Active)
        ->and($revoked->refresh()->revoked_at)->not->toBeNull()
        ->and($expired->refresh()->expires_at->isPast())->toBeTrue();

    $ids = Credential::query()->active()->pluck('id')->all();

    expect($ids)->toBe([$active->id]);
});

it('never applies a default ttl to a credential', function (): void {
    $credential = Credential::factory()->create();

    expect($credential->refresh()->expires_at)->toBeNull();
});

it('fails closed on abilities', function (): void {
    $null = Credential::factory()->create(['abilities' => null]);
    $empty = Credential::factory()->create(['abilities' => []]);
    $scoped = Credential::factory()->create(['abilities' => ['credential:read']]);

    expect($null->hasAbility('credential:read'))->toBeFalse()
        ->and($empty->hasAbility('credential:read'))->toBeFalse()
        ->and($scoped->hasAbility('credential:read'))->toBeTrue()
        ->and($scoped->hasAbility('credential:revoke'))->toBeFalse();
});

it('fetches the active public keys for a subject', function (): void {
    $active = Credential::factory()->asymmetric()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);
    $activeToo = Credential::factory()->asymmetric()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);
    Credential::factory()->asymmetric()->revoked()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);
    Credential::factory()->asymmetric()->pending()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);
    Credential::factory()->asymmetric()->expired()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);
    Credential::factory()->asymmetric()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-2',
    ]);
    Credential::factory()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'install-1',
    ]);

    $keys = Credential::activePublicKeysFor(SubjectType::Installation, 'install-1');

    expect($keys)->toEqualCanonicalizing([$active->public_key, $activeToo->public_key])
        ->and($active->public_key)->not->toBe($activeToo->public_key);
});

it('hides the secret hash from serialization', function (): void {
    $credential = Credential::factory()->create();

    expect($credential->refresh()->toArray())->not->toHaveKey('secret_hash')
        ->and($credential->toJson())->not->toContain((string) $credential->secret_hash);
});
