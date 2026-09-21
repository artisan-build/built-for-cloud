<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use FilesystemIterator;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Assert;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The frozen contract's named containment file: canary secrets driven
 * through every managed-enrolment action class — enrolment success,
 * validation refusal, changed-secret replay conflict, rotation success
 * and rotation failure — while DetectsSecretLeaks watches logger,
 * database plaintext, cache, session and queue/trace sinks, plus the
 * response channel and the exception surface of the custody store.
 */

/** @return array<string, mixed> */
function p1scEnrollmentPayload(string $secret, array $overrides = []): array
{
    return array_replace([
        'enrolment_id' => (string) Str::uuid(),
        'expected_generation' => 1,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'containment-connection',
        'organization_id' => 'containment-organization',
        'installation_id' => 'containment-installation',
        'authority_base_url' => 'https://containment-authority.example.test',
        'managed_client_secret' => $secret,
        'client_secret_generation' => 1,
    ], $overrides);
}

/** @return array{Authorization: string} */
function p1scOwnerHeaders(string $ownerToken): array
{
    return ['Authorization' => 'Bearer '.$ownerToken];
}

function p1scClaimOwner(): string
{
    [$claimToken] = app(OwnershipClaimMinter::class)->mint();
    $claim = test()->postJson('/bfc/ownership/claim', ['token' => $claimToken])->assertCreated();

    return (string) $claim->json('owner_token');
}

/** @param array<string, mixed> $payload */
function p1scEnroll(string $ownerToken, array $payload): TestResponse
{
    return test()->postJson('/bfc/managed/enrolment', $payload, p1scOwnerHeaders($ownerToken));
}

it('contains canary secrets across enrolment success, replay conflict, rotation success, rotation failure and validation refusal', function (): void {
    $ownerToken = p1scClaimOwner();

    // Enrolment success: the canary is delivered, stored encrypted, and
    // never escapes any watched sink or the response channel.
    $enrolSecret = 'containment-canary-enrol-'.bin2hex(random_bytes(8));
    $enrolment = p1scEnrollmentPayload($enrolSecret);
    $created = $this->assertNoSecretLeakage($enrolSecret, fn (): TestResponse => p1scEnroll($ownerToken, $enrolment));
    $created->assertCreated();
    $this->assertResponseCarriesNoSecret($created, $enrolSecret);

    // Changed-secret replay under the known id: 409 without the retry
    // secret leaking through the conflict path.
    $conflictSecret = 'containment-canary-conflict-'.bin2hex(random_bytes(8));
    $conflict = $this->assertNoSecretLeakage($conflictSecret, fn (): TestResponse => p1scEnroll(
        $ownerToken,
        [...$enrolment, 'managed_client_secret' => $conflictSecret],
    ));
    $conflict->assertStatus(409)->assertJsonPath('error', 'binding_conflict');
    $this->assertResponseCarriesNoSecret($conflict, $conflictSecret);

    // Rotation success: the replacement canary rotates custody without
    // egress.
    $replacement = 'containment-canary-rotate-'.bin2hex(random_bytes(8));
    $rotated = $this->assertNoSecretLeakage($replacement, fn (): TestResponse => test()->postJson(
        '/bfc/managed/enrolment/client-secret',
        [
            'rotation_id' => (string) Str::uuid(),
            'issuer' => $enrolment['issuer'],
            'connection_id' => $enrolment['connection_id'],
            'installation_id' => $enrolment['installation_id'],
            'expected_generation' => 2,
            'expected_client_secret_generation' => 1,
            'managed_client_secret' => $replacement,
        ],
        p1scOwnerHeaders($ownerToken),
    ));
    $rotated->assertOk();
    $this->assertResponseCarriesNoSecret($rotated, $replacement);

    // Rotation failure: a stale expectation refuses while carrying a
    // fresh canary that must not egress either.
    $staleSecret = 'containment-canary-stale-'.bin2hex(random_bytes(8));
    $stale = $this->assertNoSecretLeakage($staleSecret, fn (): TestResponse => test()->postJson(
        '/bfc/managed/enrolment/client-secret',
        [
            'rotation_id' => (string) Str::uuid(),
            'issuer' => $enrolment['issuer'],
            'connection_id' => $enrolment['connection_id'],
            'installation_id' => $enrolment['installation_id'],
            'expected_generation' => 2,
            'expected_client_secret_generation' => 1,
            'managed_client_secret' => $staleSecret,
        ],
        p1scOwnerHeaders($ownerToken),
    ));
    $stale->assertStatus(409)->assertJsonPath('error', 'stale_generation');
    $this->assertResponseCarriesNoSecret($stale, $staleSecret);

    // Validation refusal: the bounded-input gate refuses the payload
    // before any secret-bearing processing runs.
    $refusedSecret = 'containment-canary-validation-'.bin2hex(random_bytes(8));
    $refused = $this->assertNoSecretLeakage($refusedSecret, fn (): TestResponse => p1scEnroll(
        $ownerToken,
        p1scEnrollmentPayload($refusedSecret, ['unexpected_field' => 'refuse-me']),
    ));
    $refused->assertUnprocessable();
    $this->assertResponseCarriesNoSecret($refused, $refusedSecret);
});

it('carries no canary secret through the exception surface of the custody store', function (): void {
    $ownerToken = p1scClaimOwner();
    $secret = 'containment-canary-exception-'.bin2hex(random_bytes(8));
    p1scEnroll($ownerToken, p1scEnrollmentPayload($secret))->assertCreated();

    // The double-install backstop throws with the SQL failure chained as
    // previous: message, rendered trace, context and the whole previous
    // chain must stay marker-free.
    $second = 'containment-canary-exception-two-'.bin2hex(random_bytes(8));

    try {
        app(ManagedClientSecretStore::class)->install($second);
        Assert::fail('The double-install backstop did not refuse.');
    } catch (ManagedAuthRefused $refused) {
        $this->assertExceptionCarriesNoSecret($refused, $second);
    }
});

it('inventories every persisted-secret and configuration-seam read site in production source', function (): void {
    $root = dirname(__DIR__);
    $scan = static function (string $directory) use ($root): iterable {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        );

        foreach ($files as $file) {
            if ($file instanceof SplFileInfo && $file->getExtension() === 'php') {
                yield substr($file->getPathname(), strlen($root) + 1) => (string) file_get_contents($file->getPathname());
            }
        }
    };

    $inventory = [];

    foreach ([...iterator_to_array($scan($root.'/src')), ...iterator_to_array($scan($root.'/config'))] as $path => $code) {
        // The src/Testing instruments describe the seam; only production
        // reads count.
        if (str_starts_with($path, 'src/Testing/')) {
            continue;
        }

        foreach (explode("\n", $code) as $line) {
            if (str_contains($line, '->plaintext(')) {
                $inventory[$path]['persisted_secret_reads'] = ($inventory[$path]['persisted_secret_reads'] ?? 0) + 1;
            }

            if (str_contains($line, 'config(')
                && (str_contains($line, 'built-for-cloud.managed.client_secret')
                    || str_contains($line, 'CREDENTIAL_REFERENCE')
                    || str_contains($line, 'client_credential_reference'))) {
                $inventory[$path]['configuration_seam_reads'] = ($inventory[$path]['configuration_seam_reads'] ?? 0) + 1;
            }

            if (str_contains($line, "env('BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET')")) {
                $inventory[$path]['environment_seam_reads'] = ($inventory[$path]['environment_seam_reads'] ?? 0) + 1;
            }
        }
    }

    ksort($inventory);

    foreach ($inventory as &$counts) {
        ksort($counts);
    }
    unset($counts);

    // A new read site (or a removed one) fails this pin: the change must
    // either route through an existing consumer or extend the
    // containment coverage and this inventory together.
    expect($inventory)->toBe([
        'config/built-for-cloud.php' => ['environment_seam_reads' => 1],
        'src/ManagedAuthConnection.php' => ['configuration_seam_reads' => 1, 'persisted_secret_reads' => 1],
        'src/ManagedTransitionClient.php' => ['configuration_seam_reads' => 1, 'persisted_secret_reads' => 1],
        'src/ManagedTransitions.php' => ['configuration_seam_reads' => 1, 'persisted_secret_reads' => 1],
    ]);
});
