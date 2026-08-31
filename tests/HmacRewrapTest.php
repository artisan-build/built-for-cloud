<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

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
            ->and(Artisan::output())->toContain('holds the lock');
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

it('lets the whole dance resume after a completed rewrap: activation unpauses, and the delivery fingerprint SURVIVES re-encryption', function (): void {
    $pending = Credential::factory()->hmac()->delivered()->create();

    // The confirmation the receiver made BEFORE the APP_KEY rotation: it
    // names the delivered KEY, not the ciphertext, so a rewrap must not
    // invalidate it.
    $confirmedBeforeRewrap = (string) $pending->delivery_fingerprint;

    stageAppKeyRotation();

    $headers = ['Authorization' => 'Bearer '.auditAdminToken('rewrap-admin-'.bin2hex(random_bytes(4)))];

    $this->postJson('/bfc/credentials/'.$pending->id.'/activate', [
        'delivery_fingerprint' => $confirmedBeforeRewrap,
    ], $headers)->assertStatus(409);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);

    $this->postJson('/bfc/credentials/'.$pending->id.'/activate', [
        'delivery_fingerprint' => $confirmedBeforeRewrap,
    ], $headers)
        ->assertOk()
        ->assertJsonPath('credential.status', 'active');
});

// ------------------------------------- the writer barrier (rework Fix 4)

it('pauses hmac MINTING mid-rewrap on both transports: no ciphertext-producing path may race the completion gate', function (): void {
    Credential::factory()->hmac()->create();
    stageAppKeyRotation();

    $headers = ['Authorization' => 'Bearer '.auditAdminToken('rewrap-admin-'.bin2hex(random_bytes(4)))];

    $http = $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'raced-mint',
        'kind' => 'hmac',
    ], $headers)->assertStatus(409);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'raced-mint-cli',
        '--kind' => 'hmac',
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    expect($cliMessage)->toBe((string) $http->json('message'))
        ->and($cliMessage)->toContain('bfc:hmac:rewrap')
        ->and(Credential::query()->whereIn('subject_ref', ['raced-mint', 'raced-mint-cli'])->count())->toBe(0);

    // Non-hmac minting is untouched by the barrier.
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'bearer-still-fine',
    ], $headers)->assertCreated();

    // With the cutover complete, hmac minting resumes.
    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'raced-mint',
        'kind' => 'hmac',
    ], $headers)->assertCreated();
});

it('pauses the exchange RE-KEY mid-rewrap as a retryable claim error, leaving the row untouched; first delivery still works', function (): void {
    $result = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'rekey-raced'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );

    assert($result->secret !== null);
    $claimCode = $result->secret->reveal();

    stageAppKeyRotation();

    // FIRST delivery mid-cutover is a read (keyring) plus non-ciphertext
    // stamps: allowed.
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    /** @var Credential $row */
    $row = Credential::query()->findOrFail($result->summary->id);
    $ciphertextBefore = (string) $row->secret_ciphertext;

    // The RE-KEY writes a fresh ciphertext: paused mid-cutover, answered
    // as the claim contract's retryable server_error.
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(500)
        ->assertJsonPath('error', 'server_error');

    expect((string) $row->refresh()->secret_ciphertext)->toBe($ciphertextBefore);

    // Barrier lifted: the re-key works again.
    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
});

it('excludes EVERY ciphertext writer while the rewrap lock is held — check-through-commit, with no version mismatch to see (rework Fix 1)', function (): void {
    $headers = ['Authorization' => 'Bearer '.auditAdminToken('barrier-admin-'.bin2hex(random_bytes(4)))];

    // Everything a writer needs, prepared while the lock is free: an
    // ACTIVE key to rotate, and a delivered claim code ready to re-key.
    $mintResult = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'barrier-client'),
        MintOptions::fromInput(['kind' => 'hmac']),
    );
    $this->postJson('/bfc/credentials/'.$mintResult->summary->id.'/activate', [
        'delivery_fingerprint' => (string) $mintResult->deliveryFingerprint,
    ], $headers)->assertOk();

    $claimResult = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'barrier-rekey-client'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );
    assert($claimResult->secret !== null);
    $claimCode = $claimResult->secret->reveal();
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    // The rewrap's verification window: the sweep holds the shared lock.
    // Deliberately NO version mismatch is staged — the lock alone must
    // exclude, because the writer's version check can race the count.
    $lock = Cache::lock(HmacWriterBarrier::LOCK, 60);
    expect($lock->get())->toBeTrue();

    try {
        // hmac mint: refused retry-later.
        $mintRefused = $this->postJson('/bfc/credentials', [
            'subject_type' => 'application',
            'subject_ref' => 'locked-out-mint',
            'kind' => 'hmac',
        ], $headers)->assertStatus(409);

        expect((string) $mintRefused->json('message'))->toContain('bfc:hmac:rewrap');

        // hmac rotation's replacement mint: refused retry-later.
        $this->postJson('/bfc/credentials/'.$mintResult->summary->id.'/rotate', [], $headers)
            ->assertStatus(409);

        // The exchange redelivery: the retryable claim error, and the
        // stored ciphertext untouched.
        $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
            ->assertStatus(500)
            ->assertJsonPath('error', 'server_error');
    } finally {
        $lock->release();
    }

    expect(Credential::query()->where('subject_ref', 'locked-out-mint')->count())->toBe(0);

    // The lock released — the verification window over — every writer
    // proceeds: the zero-count was authoritative while it ran.
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'locked-out-mint',
        'kind' => 'hmac',
    ], $headers)->assertCreated();

    $this->postJson('/bfc/credentials/'.$mintResult->summary->id.'/rotate', [], $headers)->assertCreated();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
});

it('aborts the sweep when the lock lease cannot be renewed — ownership lost mid-run never overlaps two sweeps (rework Fix 4)', function (): void {
    Credential::factory()->hmac()->count(3)->create();
    stageAppKeyRotation();

    // Mid-run, right as the first row crosses, the lease lapses and a
    // rival owner takes the lock (the crash-plus-expiry scenario).
    $hijacked = false;

    DB::listen(function ($query) use (&$hijacked): void {
        if (! $hijacked && str_contains($query->sql, 'update "credentials"')) {
            $hijacked = true;
            Cache::lock(HmacWriterBarrier::LOCK)->forceRelease();
            Cache::lock(HmacWriterBarrier::LOCK, 600)->get();
        }
    });

    expect(Artisan::call('bfc:hmac:rewrap', ['--chunk' => 1]))->toBe(1);

    $output = Artisan::output();

    expect($output)->toContain('ownership was lost')
        ->and($output)->toContain('Aborting');

    // The sweep stopped instead of writing on without the lock: rows
    // remain to cross, and a re-run resumes them.
    expect(app(HmacKeyring::class)->cutoverInProgress())->toBeTrue();
});

it('does not clobber a row that was re-keyed with a fresh key while the sweep was reading it', function (): void {
    // The per-row update is guarded on the version the sweep READ, so a
    // concurrent re-key (the exchange generates a NEW signing key) that
    // lands between the sweep's read and its write is never overwritten
    // by a stale rewrite of the OLD key — the fresher write stands. The
    // race is staged deterministically: the moment the sweep's chunk
    // SELECT returns, the row is re-keyed under the write-primary with a
    // DIFFERENT plaintext, exactly the interleaving the guard exists
    // for. (The lock normally forbids this interleaving; the guard is
    // what stands when a writer is not lock-held, and it is asserted
    // here on its own.)
    $originalKey = bin2hex(random_bytes(32));
    $row = Credential::factory()->hmac($originalKey)->create();

    stageAppKeyRotation();

    $concurrentKey = bin2hex(random_bytes(32));
    $rekeyed = false;

    DB::listen(function ($query) use (&$rekeyed, $row, $concurrentKey): void {
        if (! $rekeyed && str_contains($query->sql, 'select * from "credentials"')) {
            $rekeyed = true;

            // The winning concurrent writer: a fresh key, encrypted and
            // stamped under the write-primary before the sweep writes.
            $encrypted = app(HmacKeyring::class)->encrypt($concurrentKey);
            Credential::query()->whereKey($row->id)->update([
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
            ]);
        }
    });

    expect(Artisan::call('bfc:hmac:rewrap', ['--chunk' => 1]))->toBe(0);

    /** @var Credential $row */
    $row = $row->refresh();
    $keyring = app(HmacKeyring::class);

    // The concurrent re-key WON: what is stored decrypts to the fresh
    // key under the write version — the sweep refused to overwrite it.
    expect($row->secret_key_version)->toBe($keyring->writeVersion())
        ->and($keyring->decrypt((string) $row->secret_ciphertext, $row->secret_key_version))->toBe($concurrentKey)
        ->and($keyring->cutoverInProgress())->toBeFalse();
});
