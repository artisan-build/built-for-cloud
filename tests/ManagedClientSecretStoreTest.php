<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The managed client secret's custody (P1 frozen design, "Secret
 * custody"): encrypted at rest under the HmacKeyring APP_KEY /
 * APP_PREVIOUS_KEYS precedent, content-addressed key version,
 * domain-separated retry digest, exact-key fail-closed decrypt, and
 * participation in the staged APP_KEY rewrap and its completion gate.
 */

/**
 * Stage the APP_KEY rotation over BOTH encrypted stores: new
 * write-primary, old key in the read ring. Returns the OLD version
 * fingerprint. (Named distinctly from HmacRewrapTest's helper — Pest
 * declares helpers globally.)
 */
function managedSecretStageAppKeyRotation(): string
{
    $keyring = app(HmacKeyring::class);
    $oldVersion = $keyring->writeVersion();
    $oldKey = (string) config('app.key');

    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    return $oldVersion;
}

/** @return object{client_secret_generation: int, secret_ciphertext: string, secret_key_version: string, secret_retry_digest: string} */
function managedSecretRow(): object
{
    /** @var object{client_secret_generation: int, secret_ciphertext: string, secret_key_version: string, secret_retry_digest: string} */
    return DB::table('bfc_managed_client_secrets')->where('key', ManagedClientSecretStore::KEY)->sole();
}

it('installs the singleton row encrypted under the write-primary and returns it by exact-version decrypt', function (): void {
    $secret = 'managed-store-secret-'.bin2hex(random_bytes(16));
    $store = app(ManagedClientSecretStore::class);

    $store->install($secret);

    $row = managedSecretRow();
    expect($row->client_secret_generation)->toBe(1)
        ->and($row->secret_key_version)->toBe(app(HmacKeyring::class)->writeVersion())
        ->and($row->secret_ciphertext)->not->toContain($secret)
        ->and($row->secret_retry_digest)->toBe($store->retryDigest($secret, 1))
        ->and($store->exists())->toBeTrue()
        ->and($store->generation())->toBe(1)
        ->and($store->plaintext())->toBe($secret);
});

it('refuses to install over an existing row and leaves it untouched', function (): void {
    $store = app(ManagedClientSecretStore::class);
    $store->install('first-managed-secret');
    $committed = managedSecretRow();

    expect(fn (): bool => $store->install('second-managed-secret'))->toThrow(ManagedAuthRefused::class)
        ->and(managedSecretRow())->toEqual($committed);
});

it('rotates only its own counter and refuses stale expectations or a missing row', function (): void {
    $store = app(ManagedClientSecretStore::class);

    expect(fn (): int => $store->rotate(1, 'never-installed'))->toThrow(ManagedAuthRefused::class);

    $store->install('first-managed-secret');

    expect($store->rotate(1, 'second-managed-secret'))->toBe(2)
        ->and(managedSecretRow()->client_secret_generation)->toBe(2)
        ->and(managedSecretRow()->secret_retry_digest)->toBe($store->retryDigest('second-managed-secret', 2))
        ->and($store->plaintext())->toBe('second-managed-secret');

    expect(fn (): int => $store->rotate(1, 'stale-rotation-secret'))->toThrow(ManagedAuthRefused::class)
        ->and($store->plaintext())->toBe('second-managed-secret')
        ->and(managedSecretRow()->client_secret_generation)->toBe(2);
});

it('clears the row for disconnect and is idempotent about it', function (): void {
    $store = app(ManagedClientSecretStore::class);
    $store->install('managed-secret-to-clear');

    $store->clear();
    $store->clear();

    expect($store->exists())->toBeFalse()
        ->and($store->generation())->toBeNull()
        ->and($store->plaintext())->toBeNull()
        ->and(DB::table('bfc_managed_client_secrets')->count())->toBe(0);
});

it('domain-separates the retry digest from every other hash of the same material', function (): void {
    $secret = 'digest-domain-secret';
    $digest = app(ManagedClientSecretStore::class)->retryDigest($secret, 1);

    expect($digest)->toBe(app(ManagedClientSecretStore::class)->retryDigest($secret, 1))
        ->and(strlen($digest))->toBe(64)
        ->and($digest)->not->toBe(hash('sha256', $secret))
        ->and($digest)->not->toBe(hash('sha256', hash('sha256', $secret)))
        ->and($digest)->not->toBe(app(HmacKeyring::class)->deliveryFingerprint($secret, 1))
        ->and($digest)->not->toBe(app(ManagedClientSecretStore::class)->retryDigest($secret, 2))
        ->and($digest)->not->toBe(app(ManagedClientSecretStore::class)->retryDigest('other-managed-secret', 1))
        ->and($digest)->not->toContain($secret);
});

it('fails closed when the stored key version selects no ring key', function (): void {
    $store = app(ManagedClientSecretStore::class);
    $store->install('orphaned-managed-secret');

    DB::table('bfc_managed_client_secrets')
        ->where('key', ManagedClientSecretStore::KEY)
        ->update(['secret_key_version' => 'feedfacefeedface']);

    expect(fn (): ?string => $store->plaintext())->toThrow(HmacKeyUnreadable::class);
});

it('fails closed on a mac-invalid ciphertext even under the right key version', function (): void {
    $store = app(ManagedClientSecretStore::class);
    $store->install('corrupted-managed-secret');

    DB::table('bfc_managed_client_secrets')
        ->where('key', ManagedClientSecretStore::KEY)
        ->update(['secret_ciphertext' => base64_encode('not-an-encrypted-payload')]);

    expect(fn (): ?string => $store->plaintext())->toThrow(HmacKeyUnreadable::class);
});

it('stays readable through APP_PREVIOUS_KEYS after the write-primary rotates', function (): void {
    $secret = 'ring-readable-managed-secret';
    $store = app(ManagedClientSecretStore::class);
    $store->install($secret);

    managedSecretStageAppKeyRotation();

    expect($store->plaintext())->toBe($secret)
        ->and($store->cutoverInProgress())->toBeTrue();
});

it('rides the staged APP_KEY rewrap: swept beside the hmac rows, verified, and complete', function (): void {
    Credential::factory()->hmac()->create();

    $secret = 'rewrap-managed-secret-'.bin2hex(random_bytes(16));
    $store = app(ManagedClientSecretStore::class);
    $store->install($secret);

    $oldVersion = managedSecretStageAppKeyRotation();
    $keyring = app(HmacKeyring::class);

    // Both stores report their own scope mid-cutover.
    expect($keyring->cutoverInProgress())->toBeTrue()
        ->and($store->cutoverInProgress())->toBeTrue();

    $exit = $this->assertNoSecretLeakage($secret, fn (): int => Artisan::call('bfc:hmac:rewrap'));
    $output = Artisan::output();

    expect($exit)->toBe(0)
        ->and($output)->toContain('Managed client secret re-encrypted under key-version')
        ->and($output)->toContain('1 hmac row(s) re-encrypted')
        ->and($output)->toContain('Verified zero old-version rows');

    $this->assertConsoleOutputCarriesNoSecret($output, $secret);

    $row = managedSecretRow();
    expect($row->secret_key_version)->toBe($keyring->writeVersion())
        ->and($row->secret_key_version)->not->toBe($oldVersion)
        ->and($row->client_secret_generation)->toBe(1)
        ->and($row->secret_retry_digest)->toBe($store->retryDigest($secret, 1))
        ->and($store->plaintext())->toBe($secret)
        ->and($store->cutoverInProgress())->toBeFalse()
        ->and($keyring->cutoverInProgress())->toBeFalse();
});

it('refuses rewrap completion while the managed secret version selects no ring key, and resumes once the ring is restored', function (): void {
    $secret = 'unrewrapable-managed-secret';
    $store = app(ManagedClientSecretStore::class);
    $store->install($secret);

    $oldVersion = managedSecretStageAppKeyRotation();

    // The key left the ring entirely: the row is unreadable and must be
    // reported and RETAINED, never dropped.
    DB::table('bfc_managed_client_secrets')
        ->where('key', ManagedClientSecretStore::KEY)
        ->update(['secret_key_version' => 'feedfacefeedface']);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(1);

    $output = Artisan::output();
    expect($output)->toContain('The managed client secret could not be re-encrypted')
        ->and($output)->toContain('still carries a non-primary key-version')
        ->and($output)->toContain('NOT complete');

    expect($store->cutoverInProgress())->toBeTrue()
        ->and(DB::table('bfc_managed_client_secrets')->count())->toBe(1);

    // Ring restored (the old key returns to APP_PREVIOUS_KEYS and the
    // row's true version with it): the sweep resumes and completes.
    DB::table('bfc_managed_client_secrets')
        ->where('key', ManagedClientSecretStore::KEY)
        ->update(['secret_key_version' => $oldVersion]);

    expect(Artisan::call('bfc:hmac:rewrap'))->toBe(0)
        ->and($store->plaintext())->toBe($secret)
        ->and($store->cutoverInProgress())->toBeFalse();
});

it('refuses secret rotation mid-cutover while the stored row is not on the write-primary', function (): void {
    $secret = 'mid-cutover-managed-secret';
    $store = app(ManagedClientSecretStore::class);
    $store->install($secret);

    managedSecretStageAppKeyRotation();

    expect(fn (): int => $store->rotate(1, 'raced-replacement-secret'))
        ->toThrow(RewrapInProgress::class);

    $row = managedSecretRow();
    expect($row->client_secret_generation)->toBe(1)
        ->and($store->plaintext())->toBe($secret)
        ->and($store->cutoverInProgress())->toBeTrue();

    // A fresh enrolment writes no old-version row and stays allowed
    // mid-cutover — clear first, then install lands under the
    // write-primary.
    $store->clear();
    $store->install('fresh-write-primary-secret');

    expect(managedSecretRow()->secret_key_version)->toBe(app(HmacKeyring::class)->writeVersion())
        ->and($store->plaintext())->toBe('fresh-write-primary-secret');
});
