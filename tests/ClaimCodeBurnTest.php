<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use RuntimeException;

uses(RefreshDatabase::class);

it('consumes the claim code exactly once when two resolutions race at the affected-rows gate', function (): void {
    [$claimCode, $durable] = burnExchange('race@example.test');

    $registry = app(TokenRegistry::class);

    $consumptionWrites = 0;
    $competitorFired = false;

    DB::listen(function (QueryExecuted $query) use (&$consumptionWrites, &$competitorFired, $durable, $registry): void {
        if (preg_match('/^\s*update\b/i', $query->sql) === 1
            && str_contains($query->sql, 'onboarding_tokens')
            && str_contains($query->sql, 'consumed_at')) {
            $consumptionWrites++;
        }

        // Between the loser's read of the api_tokens row and its
        // conditional UPDATE, the competing process resolves first — so the
        // loser enters the burn with a stale NULL last_used_at, its
        // conditional update affects zero rows, and the gate must stop it
        // consuming.
        if (! $competitorFired
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'token_hash')) {
            $competitorFired = true;
            $registry->resolve($durable);
        }
    });

    expect($registry->resolve($durable))->toBe('race@example.test');

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($competitorFired)->toBeTrue()
        ->and($code->consumed_at)->not->toBeNull()
        ->and($consumptionWrites)->toBe(1);
});

it('leaves the code unconsumed when the process dies between the usage write and the consumption', function (): void {
    [$claimCode, $durable] = burnExchange('death@example.test');

    $registry = app(TokenRegistry::class);

    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*update\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'last_used_at')) {
            $armed = false;

            throw new RuntimeException('simulated process death after the usage write');
        }
    });

    expect(fn (): ?string => $registry->resolve($durable))->toThrow(RuntimeException::class);

    $tokenRow = ApiToken::query()->where('name', 'death@example.test')->firstOrFail();
    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // BOTH writes rolled back: the code is unconsumed rather than
    // orphaned-unburned, and the token shows no use.
    expect($tokenRow->last_used_at)->toBeNull()
        ->and($code->consumed_at)->toBeNull();

    // A retry then succeeds and burns normally.
    expect($registry->resolve($durable))->toBe('death@example.test')
        ->and($code->refresh()->consumed_at)->not->toBeNull()
        ->and($tokenRow->refresh()->last_used_at)->not->toBeNull();
});

it('burns through the HTTP Basic path the way Crate presents the durable', function (): void {
    [$claimCode, $durable] = burnExchange('crate@example.test');

    // Crate speaks HTTP Basic out of auth.json: the password half is the
    // secret. Present it exactly that way and extract it the way crate's
    // middleware does before resolution.
    $header = 'Basic '.base64_encode('composer:'.$durable);

    $decoded = (string) base64_decode(substr($header, 6), true);
    [, $password] = explode(':', $decoded, 2);

    expect(app(TokenRegistry::class)->resolve($password))->toBe('crate@example.test');

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($code->consumed_at)->not->toBeNull();
});

it('does not revoke the live durable at issue and revokes both ways at exchange', function (): void {
    // A working integration: a live durable of the same name+scope, linked
    // to no claim code at all.
    $livePlaintext = mintApiToken('person@example.test', [Scope::Consume->value]);
    $registry = app(TokenRegistry::class);

    expect($registry->resolve($livePlaintext))->toBe('person@example.test');

    $claimCode = issueOnboardingToken('person@example.test');

    // The code sitting in an inbox breaks nothing on send day.
    expect($registry->resolve($livePlaintext))->toBe('person@example.test');

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    // After exchange: the name+scope revocation caught the unlinked live
    // durable, and exactly one live durable remains — the new one.
    expect($registry->resolve($livePlaintext))->toBeNull();

    expect(ApiToken::query()->where('name', 'person@example.test')->resolvable()->count())->toBe(1)
        ->and($registry->resolve((string) $exchange->json('durable_token')))->toBe('person@example.test');
});

it('consumes at exchange under the locked conditional update when the declaration declares at_exchange', function (): void {
    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class implements CredentialDeclaration, DeclaresBurnMode
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function burnMode(): BurnMode
        {
            return BurnMode::AtExchange;
        }
    });

    $claimCode = issueOnboardingToken('reel@example.test');

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // Redemption IS the burn in this mode.
    expect($code->consumed_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');

    // The durable it minted still works, and using it consumes nothing
    // further.
    expect(app(TokenRegistry::class)->resolve((string) $exchange->json('durable_token')))->toBe('reel@example.test');
});

/**
 * Issue a claim code for the address and exchange it, leaving the durable
 * unused so the code is still pending (make-before-break).
 *
 * @return array{string, string} the claim code and the durable plaintext
 */
function burnExchange(string $email): array
{
    $claimCode = issueOnboardingToken($email);

    $exchange = test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    return [$claimCode, (string) $exchange->json('durable_token')];
}
