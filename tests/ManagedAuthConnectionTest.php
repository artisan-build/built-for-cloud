<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * The persisted-secret precedence in {@see ManagedAuthConnection::current()}
 * (P1 frozen design, "Secret custody"): persisted ciphertext wins over the
 * environment, unreadable persisted state refuses fail-closed with NO
 * fallback, and the environment seam answers only while no ciphertext
 * exists (the Owner-driven adopt path — follow-up #150 owns its removal).
 */
function managedConnectionAuthority(): void
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'managed-secret-connection',
        'organization_id' => 'managed-secret-organization',
        'installation_id' => 'managed-secret-installation',
        'authority_base_url' => 'https://managed-secret-authority.example.test',
    ]);
}

it('prefers the persisted secret over the environment fallback while ciphertext exists', function (): void {
    managedConnectionAuthority();
    app(ManagedClientSecretStore::class)->install('persisted-managed-secret');
    config(['built-for-cloud.managed.client_secret' => 'wrong-environment-secret']);

    expect(ManagedAuthConnection::current()->clientSecret)->toBe('persisted-managed-secret');
});

it('refuses fail-closed when the persisted secret is unreadable and never falls back to the environment', function (string $breakage): void {
    managedConnectionAuthority();
    app(ManagedClientSecretStore::class)->install('unreadable-managed-secret');
    config(['built-for-cloud.managed.client_secret' => 'would-be-fallback-secret']);

    if ($breakage === 'unknown key version') {
        DB::table('bfc_managed_client_secrets')
            ->where('key', ManagedClientSecretStore::KEY)
            ->update(['secret_key_version' => 'feedfacefeedface']);
    } elseif ($breakage === 'key left the ring') {
        config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        config()->set('app.previous_keys', null);
    } else {
        DB::table('bfc_managed_client_secrets')
            ->where('key', ManagedClientSecretStore::KEY)
            ->update(['secret_ciphertext' => base64_encode('not-an-encrypted-payload')]);
    }

    expect(fn (): string => ManagedAuthConnection::current()->clientSecret)->toThrow(ManagedAuthRefused::class);
})->with(['unknown key version', 'key left the ring', 'corrupted ciphertext']);

it('uses the environment only while no persisted secret exists, and refuses when neither answers', function (): void {
    managedConnectionAuthority();

    config(['built-for-cloud.managed.client_secret' => 'environment-managed-secret']);
    expect(ManagedAuthConnection::current()->clientSecret)->toBe('environment-managed-secret');

    config(['built-for-cloud.managed.client_secret' => null]);
    expect(fn (): ManagedAuthConnection => ManagedAuthConnection::current())->toThrow(ManagedAuthRefused::class);
});
