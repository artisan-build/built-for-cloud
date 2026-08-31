<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * The hmac kind at rest (PRD 1.21 / D9.1, SEC-V3-08): the signing key is
 * ENCRYPTED — never the plaintext, never a hash — every ciphertext carries
 * its encryption key-version, and the keyring reads old versions through
 * app.previous_keys while writing only under the current app.key.
 */

// ------------------------------------------------------------ at rest

it('stores the hmac signing key as ciphertext, not the key and not a hash (locked AC 11)', function (): void {
    $signingKey = 'hmac-signing-key-'.bin2hex(random_bytes(16));

    $credential = Credential::factory()->hmac($signingKey)->create();

    /** @var stdClass $row */
    $row = DB::table('credentials')->where('id', $credential->id)->first();

    expect($row->secret_ciphertext)->not->toBeNull()
        ->and($row->secret_ciphertext)->not->toContain($signingKey)
        ->and($row->secret_ciphertext)->not->toBe(hash('sha256', $signingKey))
        ->and($row->secret_hash)->toBeNull()
        ->and($row->secret_key_version)->toBe(app(HmacKeyring::class)->writeVersion())
        ->and(app(HmacKeyring::class)->decrypt((string) $row->secret_ciphertext, (string) $row->secret_key_version))
        ->toBe($signingKey);
});

it('never serializes the ciphertext out of the model', function (): void {
    $credential = Credential::factory()->hmac()->create();

    expect($credential->toArray())->not->toHaveKeys(['secret_ciphertext', 'secret_hash']);
});

// ------------------------------------------------------- model guards

it('refuses a secret hash on an hmac row: a hash cannot sign', function (): void {
    Credential::query()->create([
        'kind' => CredentialKind::Hmac,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'postmaster',
        'secret_hash' => hash('sha256', 'anything'),
    ]);
})->throws(InvalidArgumentException::class, 'never hashed');

it('refuses a public key on an hmac row', function (): void {
    $hmac = Credential::factory()->hmac()->create();

    $hmac->forceFill(['public_key' => Credential::factory()::generatePublicKey()])->save();
})->throws(InvalidArgumentException::class, 'never carries a public key');

it('refuses a ciphertext on any non-hmac kind', function (): void {
    $bearer = Credential::factory()->create();

    $bearer->forceFill([
        'secret_ciphertext' => 'anything',
        'secret_key_version' => 'aaaabbbbccccdddd',
    ])->save();
})->throws(InvalidArgumentException::class, 'Only the hmac kind');

it('refuses a ciphertext without its key-version and a key-version without its ciphertext', function (): void {
    $hmac = Credential::factory()->hmac()->create();

    expect(fn () => $hmac->forceFill(['secret_key_version' => null])->save())
        ->toThrow(InvalidArgumentException::class, 'travel together');

    $hmac->refresh();

    expect(fn () => $hmac->forceFill(['secret_ciphertext' => null])->save())
        ->toThrow(InvalidArgumentException::class, 'travel together');
});

it('keeps the hmac lifecycle columns out of mass assignment: delivery and activation cannot be forged through fill', function (): void {
    $encrypted = app(HmacKeyring::class)->encrypt('key-material');

    $credential = new Credential;
    $credential->fill([
        'kind' => CredentialKind::Hmac,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'postmaster',
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'delivered_at' => now(),
        'activated_at' => now(),
    ]);

    expect($credential->secret_ciphertext)->toBeNull()
        ->and($credential->secret_key_version)->toBeNull()
        ->and($credential->delivered_at)->toBeNull()
        ->and($credential->activated_at)->toBeNull();
});

// ------------------------------------------------------------ keyring

it('round-trips through the keyring under the current app key, stamping the write version', function (): void {
    $keyring = app(HmacKeyring::class);

    $encrypted = $keyring->encrypt('the-signing-key');

    expect($encrypted->keyVersion)->toBe($keyring->writeVersion())
        ->and($encrypted->keyVersion)->toMatch('/^[0-9a-f]{16}$/')
        ->and($keyring->decrypt($encrypted->ciphertext, $encrypted->keyVersion))->toBe('the-signing-key');
});

it('reads an old-version ciphertext through app.previous_keys after the app key rotates (SEC-V3-08 stage 1)', function (): void {
    $keyring = app(HmacKeyring::class);

    $oldKey = (string) config('app.key');
    $encryptedUnderOld = $keyring->encrypt('survives-rotation');
    $oldVersion = $encryptedUnderOld->keyVersion;

    // The staged rotation: new APP_KEY, old key in APP_PREVIOUS_KEYS.
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    expect($keyring->writeVersion())->not->toBe($oldVersion)
        ->and($keyring->decrypt($encryptedUnderOld->ciphertext, $oldVersion))->toBe('survives-rotation');
});

it('fails loudly, naming the version, when a ciphertext key-version is in no ring key', function (): void {
    $keyring = app(HmacKeyring::class);

    $encrypted = $keyring->encrypt('now-orphaned');

    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', []);

    expect(fn (): string => $keyring->decrypt($encrypted->ciphertext, $encrypted->keyVersion))
        ->toThrow(HmacKeyUnreadable::class, $encrypted->keyVersion);
});

it('refuses a wrong version even while the ciphertext is decryptable by a ring key', function (): void {
    // The version SELECTS the key; it is never a hint. A row claiming a
    // version that matches no ring key must fail loudly even when the
    // ciphertext itself would decrypt under one of them — the opposite
    // behaviour ("try the whole ring, return whatever decrypts") is the
    // mac-roulette this method exists to prevent, and a test that only
    // reads correctly-stamped rows cannot tell the two apart.
    $keyring = app(HmacKeyring::class);

    $oldKey = (string) config('app.key');
    $encryptedUnderOld = $keyring->encrypt('decryptable-but-mislabelled');

    // Staged rotation: the old key STAYS in the ring, so the ciphertext
    // is decryptable — but the row carries a version nothing stamps.
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    expect(fn (): string => $keyring->decrypt($encryptedUnderOld->ciphertext, str_repeat('0', 16)))
        ->toThrow(HmacKeyUnreadable::class);
});

it('reports an APP_KEY cutover in progress exactly while any hmac row carries a non-primary key-version', function (): void {
    $keyring = app(HmacKeyring::class);

    expect($keyring->cutoverInProgress())->toBeFalse();

    Credential::factory()->hmac()->create();

    expect($keyring->cutoverInProgress())->toBeFalse();

    $oldKey = (string) config('app.key');
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    expect($keyring->cutoverInProgress())->toBeTrue();
});
