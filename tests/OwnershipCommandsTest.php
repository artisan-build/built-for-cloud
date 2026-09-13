<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['built-for-cloud.product' => 'Sink']);
    Queue::fake();

});

it('mints a pending claim in execute mode when ownership is unclaimed', function (): void {
    $plaintext = 'unclaimed-bootstrap-token';
    $hash = hash('sha256', $plaintext);

    $exitCode = Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => $hash,
    ]);

    expect($exitCode)->toBe(0)
        ->and(Artisan::output())->toContain('Ownership claim minted.');

    $claim = OwnershipClaim::query()->sole();

    expect($claim->token_hash)->toBe($hash)
        ->and($claim->consumed_at)->toBeNull()
        ->and(OwnershipClaim::resolve($plaintext)?->getKey())->toBe($claim->getKey());
});

it('mints a claim that the claim endpoint exchanges for a credential-admin owner credential', function (): void {
    $plaintext = 'exchangeable-bootstrap-token';

    Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => hash('sha256', $plaintext),
    ]);

    $response = $this->postJson('/bfc/ownership/claim', ['token' => $plaintext]);

    $response->assertCreated();

    $ownership = Ownership::current();
    $ownerCredential = Credential::query()->whereKey($ownership?->owner_credential_id)->firstOrFail();

    expect($ownerCredential->kind)->toBe(CredentialKind::Bearer)
        ->and($ownerCredential->subject_type)->toBe(SubjectType::Operator)
        ->and($ownerCredential->subject_ref)->toBe('owner')
        ->and($ownerCredential->name)->toBe('owner')
        ->and($ownerCredential->abilities)->toBe([EnsureCredentialAdmin::ABILITY])
        ->and($ownerCredential->status)->toBe(CredentialStatus::Active)
        ->and($ownerCredential->secret_hash)->toBe(hash('sha256', (string) $response->json('owner_token')));

    $this->getJson('/bfc/credentials', ownerCommandHeaders((string) $response->json('owner_token')))
        ->assertOk();
});

it('refuses to mint a claim when ownership is already claimed', function (): void {
    claimOwnerForCommandTests();

    $ownership = Ownership::current();

    $exitCode = Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => hash('sha256', 'hostile-bootstrap-token'),
    ]);

    expect($exitCode)->not->toBe(0)
        ->and(Artisan::output())->toContain('Ownership is already claimed.')
        ->and(OwnershipClaim::query()->pending()->count())->toBe(0)
        ->and(Ownership::current()?->owner_credential_id)->toBe($ownership?->owner_credential_id)
        ->and(Credential::query()->count())->toBe(1);
});

it('refuses to mint a duplicate claim for a hash that is already registered', function (): void {
    $hash = hash('sha256', 'duplicate-bootstrap-token');

    Artisan::call('bfc:ownership:mint-claim', ['--execute' => true, '--hash' => $hash]);
    $exitCode = Artisan::call('bfc:ownership:mint-claim', ['--execute' => true, '--hash' => $hash]);

    expect($exitCode)->not->toBe(0)
        ->and(OwnershipClaim::query()->count())->toBe(1);
});

it('rejects a claim hash that is not a sha256 digest', function (): void {
    $exitCode = Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => 'not-a-hash',
    ]);

    expect($exitCode)->not->toBe(0)
        ->and(OwnershipClaim::query()->count())->toBe(0);
});

it('runs mint-claim in driver mode without sending plaintext to cloud', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Ownership claim minted.\\n","exitCode":0}'),
    ]);

    Artisan::call('bfc:ownership:mint-claim', ['--environment' => 'env-1']);

    $output = Artisan::output();

    preg_match('/Save this claim token - shown once: ([0-9a-f]{64})/', $output, $matches);
    $plaintext = $matches[1] ?? '';
    $hash = hash('sha256', $plaintext);

    expect($plaintext)->not->toBe('')
        ->and(substr_count($output, $plaintext))->toBe(1);

    Process::assertRan(function ($process) use ($plaintext, $hash): bool {
        $command = $process->command[4] ?? '';

        return is_string($command)
            && str_contains($command, 'bfc:ownership:mint-claim')
            && str_contains($command, '--execute')
            && str_contains($command, "--hash='".$hash."'")
            && ! str_contains($command, $plaintext);
    });
});

it('reports the remote failure exit code without printing a claim token', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Ownership is already claimed.\\n","exitCode":1}'),
    ]);

    $exitCode = Artisan::call('bfc:ownership:mint-claim', ['--environment' => 'env-1']);

    expect($exitCode)->toBe(1)
        ->and(Artisan::output())->not->toContain('Save this claim token');
});

it('remints the owner token for the current owner and revokes the previous one', function (): void {
    $previousPlaintext = claimOwnerForCommandTests();
    $ownership = Ownership::current();
    $previousCredentialId = $ownership?->owner_credential_id;
    $otherOwnerCredential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'owner',
        'name' => 'renamed-owner',
        'abilities' => [EnsureCredentialAdmin::ABILITY],
    ]);
    $newPlaintext = 'reminted-owner-token';

    $exitCode = Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => hash('sha256', $newPlaintext),
    ]);

    expect($exitCode)->toBe(0)
        ->and(Artisan::output())->toContain('Owner token reminted.');

    $reminted = Ownership::current();
    $newCredential = Credential::query()->whereKey($reminted?->owner_credential_id)->firstOrFail();
    $previousCredential = Credential::query()->whereKey($previousCredentialId)->firstOrFail();

    expect(Ownership::query()->count())->toBe(1)
        ->and($reminted?->owner_credential_id)->not->toBe($previousCredentialId)
        ->and($reminted?->webhook_secret)->toBe($ownership?->webhook_secret)
        ->and($newCredential->subject_type)->toBe(SubjectType::Operator)
        ->and($newCredential->subject_ref)->toBe('owner')
        ->and($newCredential->abilities)->toBe([EnsureCredentialAdmin::ABILITY])
        ->and($newCredential->secret_hash)->toBe(hash('sha256', $newPlaintext))
        ->and($previousCredential->revoked_at)->not->toBeNull()
        ->and($otherOwnerCredential->refresh()->revoked_at)->not->toBeNull()
        ->and(Credential::query()->where('secret_hash', $newPlaintext)->exists())->toBeFalse();

    $this->getJson('/bfc/credentials', ownerCommandHeaders($newPlaintext))->assertOk();
    $this->getJson('/bfc/credentials', ownerCommandHeaders($previousPlaintext))->assertUnauthorized();
});

it('transfers from an exact owner credential', function (): void {
    claimOwnerForCommandTests();

    $ownership = Ownership::current();
    $previousCredentialId = $ownership?->owner_credential_id;
    $claimPlaintext = 'unified-transfer-claim';
    $claim = OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($claimPlaintext),
    ]);

    $ownership?->forceFill(['pending_claim_id' => $claim->getKey()])->save();

    $response = $this->postJson('/bfc/ownership/claim', ['token' => $claimPlaintext])->assertCreated();
    $transferred = Ownership::current();

    expect($transferred?->owner_credential_id)->not->toBe($previousCredentialId)
        ->and(Credential::query()->whereKey($previousCredentialId)->sole()->revoked_at)->not->toBeNull();

    $this->getJson('/bfc/credentials', ownerCommandHeaders((string) $response->json('owner_token')))->assertOk();
});

it('refuses to remint an owner token when ownership is unclaimed', function (): void {
    $exitCode = Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => hash('sha256', 'orphan-owner-token'),
    ]);

    expect($exitCode)->not->toBe(0)
        ->and(Artisan::output())->toContain('Ownership is not claimed.')
        ->and(Credential::query()->count())->toBe(0)
        ->and(Ownership::query()->count())->toBe(0);
});

it('rejects an owner token hash that is not a sha256 digest', function (): void {
    claimOwnerForCommandTests();

    $ownership = Ownership::current();

    $exitCode = Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => 'not-a-hash',
    ]);

    expect($exitCode)->not->toBe(0)
        ->and(Ownership::current()?->owner_credential_id)->toBe($ownership?->owner_credential_id)
        ->and(Credential::query()->count())->toBe(1);
});

it('runs remint in driver mode without sending plaintext to cloud', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"Owner token reminted.\\n","exitCode":0}'),
    ]);

    Artisan::call('bfc:ownership:remint-owner-token', ['--environment' => 'env-1']);

    $output = Artisan::output();

    preg_match('/Save this token - shown once: (tok_[0-9a-f]{64})/', $output, $matches);
    $plaintext = $matches[1] ?? '';
    $hash = hash('sha256', $plaintext);

    expect($plaintext)->not->toBe('')
        ->and(substr_count($output, $plaintext))->toBe(1);

    Process::assertRan(function ($process) use ($plaintext, $hash): bool {
        $command = $process->command[4] ?? '';

        return is_string($command)
            && str_contains($command, 'bfc:ownership:remint-owner-token')
            && str_contains($command, '--execute')
            && str_contains($command, "--hash='".$hash."'")
            && ! str_contains($command, $plaintext);
    });
});

it('persists only hashes for tokens minted by the ownership commands', function (): void {
    $claimPlaintext = 'hash-only-claim-token';
    $ownerPlaintext = 'hash-only-owner-token';

    Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => hash('sha256', $claimPlaintext),
    ]);

    $this->postJson('/bfc/ownership/claim', ['token' => $claimPlaintext])->assertCreated();

    Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => hash('sha256', $ownerPlaintext),
    ]);

    $claimRows = OwnershipClaim::query()->get()->map(fn (OwnershipClaim $claim): string => $claim->token_hash);
    $credentialRows = Credential::query()->get()->map(fn (Credential $credential): ?string => $credential->secret_hash);

    expect($claimRows)->toContain(hash('sha256', $claimPlaintext))
        ->and($claimRows)->not->toContain($claimPlaintext)
        ->and($credentialRows)->toContain(hash('sha256', $ownerPlaintext))
        ->and($credentialRows)->not->toContain($ownerPlaintext);
});

function claimOwnerForCommandTests(string $claimToken = 'command-initial-claim'): string
{
    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($claimToken),
    ]);

    $response = test()->postJson('/bfc/ownership/claim', ['token' => $claimToken]);
    $response->assertCreated();

    return (string) $response->json('owner_token');
}

/**
 * @return array{Authorization: string}
 */
function ownerCommandHeaders(string $plainTextToken): array
{
    return ['Authorization' => 'Bearer '.$plainTextToken];
}
