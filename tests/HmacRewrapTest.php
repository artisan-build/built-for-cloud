<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The staged APP_KEY rewrap (SEC-V3-08, locked AC 6): old ciphertexts
 * readable via the keyring at every stage, `bfc:hmac:rewrap` locked and
 * restartable, completion gated on verify-zero-old-version-rows, and the
 * activation/rotation pause covered beside the verbs' own suites.
 */

/**
 * Stage the APP_KEY rotation: new write-primary, old key in the read
 * keyring. Returns the OLD version fingerprint.
 */
function stageAppKeyRotation(): string
{
    $keyring = app(HmacKeyring::class);
    $oldVersion = $keyring->writeVersion();
    $oldKey = (string) config('app.key');

    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    return $oldVersion;
}

it('rewraps every hmac ciphertext — active, pending, grace, revoked — and verifies zero old-version rows (locked AC 6)', function (): void {
    $knownKey = bin2hex(random_bytes(32));

    $active = Credential::factory()->hmac($knownKey)->activated()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);
    $pending = Credential::factory()->hmac()->delivered()->create();
    $grace = Credential::factory()->hmac()->activated()->create(['expires_at' => now()->addMinutes(30)]);
    Credential::query()->whereKey($grace->id)->update(['rotated_at' => now()]);
    $revoked = Credential::factory()->hmac()->revoked()->create();

    $oldVersion = stageAppKeyRotation();
    $keyring = app(HmacKeyring::class);

    expect($keyring->cutoverInProgress())->toBeTrue();

    // MID-CUTOVER, before any rewrap: old-version ciphertexts stay
    // readable through the keyring — verification keeps working.
    $envelope = new HmacEnvelope(
        keyId: $active->id,
        eventType: 'evt',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('app.url'),
    );
    $header = $envelope->headerValue(hash_hmac('sha256', $envelope->canonical('body'), $knownKey));

    expect(app(HmacVerifier::class)->verify(new Subject(SubjectType::ExternalConsumer, 'acme'), $header, 'body')->id)
        ->toBe($active->id);

    // The sweep, watched for leaks: no key material in any channel.
    $exit = $this->assertNoSecretLeakage($knownKey, fn (): int => Artisan::call('bfc:hmac:rewrap'));
    $output = Artisan::output();

    expect($exit)->toBe(0)
        ->and($output)->toContain('4 hmac row(s) re-encrypted')
        ->and($output)->toContain('Verified zero old-version rows');

    $this->assertConsoleOutputCarriesNoSecret($output, $knownKey);

    // Every row — the revoked one included — is on the new version, and
    // the plaintexts survived the re-encryption byte for byte.
    $newVersion = $keyring->writeVersion();

    foreach ([$active, $pending, $grace, $revoked] as $row) {
        $row->refresh();

        expect($row->secret_key_version)->toBe($newVersion)
            ->and($row->secret_key_version)->not->toBe($oldVersion);
    }

    expect($keyring->decrypt((string) $active->refresh()->secret_ciphertext, $active->secret_key_version))->toBe($knownKey)
        ->and($keyring->cutoverInProgress())->toBeFalse();
});

it('is restartable: a run after a died sweep picks up exactly the rows still on the old version', function (): void {
    Credential::factory()->hmac()->count(3)->create();

    stageAppKeyRotation();
    $keyring = app(HmacKeyring::class);

    // Simulate the died previous run: one row already made it across.
    /** @var Credential $alreadyDone */
    $alreadyDone = Credential::query()->where('kind', CredentialKind::Hmac->value)->orderBy('id')->firstOrFail();
    $plaintext = $keyring->decrypt((string) $alreadyDone->secret_ciphertext, $alreadyDone->secret_key_version);
    $encrypted = $keyring->encrypt($plaintext);
    Credential::query()->whereKey($alreadyDone->id)->update([
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
    ]);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0)
        ->and(Artisan::output())->toContain('2 hmac row(s) re-encrypted')
        ->and($keyring->cutoverInProgress())->toBeFalse();
});

it('refuses completion while any old-version row remains, naming it, without losing the progress it made', function (): void {
    $healthy = Credential::factory()->hmac()->create();
    $orphaned = Credential::factory()->hmac()->create();

    stageAppKeyRotation();

    // A row whose ciphertext key left the ring entirely: unreadable.
    Credential::query()->whereKey($orphaned->id)->update(['secret_key_version' => 'feedfacefeedface']);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(1);

    $output = Artisan::output();

    expect($output)->toContain($orphaned->id)
        ->and($output)->toContain('NOT complete')
        ->and($output)->toContain('1 hmac row(s) still carry');

    // Progress stands: the healthy row crossed; the cutover stays open
    // (activation/rotation stay paused) until the ring is fixed.
    expect($healthy->refresh()->secret_key_version)->toBe(app(HmacKeyring::class)->writeVersion())
        ->and(app(HmacKeyring::class)->cutoverInProgress())->toBeTrue();
});

it('admits one run at a time: a second invocation refuses while the lock is held', function (): void {
    Credential::factory()->hmac()->create();
    stageAppKeyRotation();

    $lock = Cache::lock('bfc:hmac:rewrap', 60);
    expect($lock->get())->toBeTrue();

    try {
        expect(Artisan::call('bfc:hmac:rewrap'))->toBe(1)
            ->and(Artisan::output())->toContain('Another rewrap run holds the lock');
    } finally {
        $lock->release();
    }

    // With the lock gone the same invocation completes.
    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);
});

it('succeeds as a no-op when nothing needs rewrapping', function (): void {
    Credential::factory()->hmac()->create();

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('0 hmac row(s) re-encrypted')
        ->and($output)->toContain('Verified zero old-version rows');
});

it('lets the whole dance resume after a completed rewrap: activation unpauses', function (): void {
    $pending = Credential::factory()->hmac()->delivered()->create();

    stageAppKeyRotation();

    $headers = ['Authorization' => 'Bearer '.auditAdminToken('rewrap-admin-'.bin2hex(random_bytes(4)))];

    $this->postJson('/bfc/credentials/'.$pending->id.'/activate', [], $headers)->assertStatus(409);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);

    $this->postJson('/bfc/credentials/'.$pending->id.'/activate', [], $headers)
        ->assertOk()
        ->assertJsonPath('credential.status', 'active');
});
