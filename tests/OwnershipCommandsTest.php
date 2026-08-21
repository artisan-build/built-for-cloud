<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['built-for-cloud.product' => 'Sink']);
    Queue::fake();

    Route::middleware('bfc.token.admin')->post('/command-owner-gate', fn (): array => ['ok' => true]);
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

it('mints a claim that the claim endpoint exchanges for an admin owner token', function (): void {
    $plaintext = 'exchangeable-bootstrap-token';

    Artisan::call('bfc:ownership:mint-claim', [
        '--execute' => true,
        '--hash' => hash('sha256', $plaintext),
    ]);

    $response = $this->postJson('/bfc/ownership/claim', ['token' => $plaintext]);

    $response->assertCreated();

    $ownerToken = ApiToken::query()->whereKey(Ownership::current()?->owner_token_id)->firstOrFail();

    expect($ownerToken->abilities)->toBe([Scope::Admin->value]);

    $this->postJson('/command-owner-gate', [], ownerCommandHeaders((string) $response->json('owner_token')))
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
        ->and(Ownership::current()?->owner_token_id)->toBe($ownership?->owner_token_id);
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
    $previousTokenId = $ownership?->owner_token_id;
    $newPlaintext = 'reminted-owner-token';

    $exitCode = Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => hash('sha256', $newPlaintext),
    ]);

    expect($exitCode)->toBe(0)
        ->and(Artisan::output())->toContain('Owner token reminted.');

    $reminted = Ownership::current();
    $newToken = ApiToken::query()->whereKey($reminted?->owner_token_id)->firstOrFail();
    $previousToken = ApiToken::query()->whereKey($previousTokenId)->firstOrFail();

    expect(Ownership::query()->count())->toBe(1)
        ->and($reminted?->owner_token_id)->not->toBe($previousTokenId)
        ->and($reminted?->webhook_secret)->toBe($ownership?->webhook_secret)
        ->and($newToken->name)->toBe('owner')
        ->and($newToken->abilities)->toBe([Scope::Admin->value])
        ->and($previousToken->revoked_at)->not->toBeNull();

    $this->postJson('/command-owner-gate', [], ownerCommandHeaders($newPlaintext))->assertOk();
    $this->postJson('/command-owner-gate', [], ownerCommandHeaders($previousPlaintext))->assertUnauthorized();
});

it('refuses to remint an owner token when ownership is unclaimed', function (): void {
    $exitCode = Artisan::call('bfc:ownership:remint-owner-token', [
        '--execute' => true,
        '--hash' => hash('sha256', 'orphan-owner-token'),
    ]);

    expect($exitCode)->not->toBe(0)
        ->and(Artisan::output())->toContain('Ownership is not claimed.')
        ->and(ApiToken::query()->count())->toBe(0)
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
        ->and(Ownership::current()?->owner_token_id)->toBe($ownership?->owner_token_id)
        ->and(ApiToken::query()->count())->toBe(1);
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
    $tokenRows = ApiToken::query()->get()->map(fn (ApiToken $token): string => $token->token_hash);

    expect($claimRows)->toContain(hash('sha256', $claimPlaintext))
        ->and($claimRows)->not->toContain($claimPlaintext)
        ->and($tokenRows)->toContain(hash('sha256', $ownerPlaintext))
        ->and($tokenRows)->not->toContain($ownerPlaintext);
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
