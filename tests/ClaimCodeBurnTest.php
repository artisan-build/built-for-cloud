<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ApiTokenMinter;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\MintedDurableCredential;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use RuntimeException;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

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

it('fails authentication when the durable is revoked and the code relinked mid-resolution', function (): void {
    [$claimCode, $firstDurable] = burnExchange('toctou@example.test');

    $registry = app(TokenRegistry::class);

    $reclaimed = false;
    $secondDurable = null;

    DB::listen(function (QueryExecuted $query) use (&$reclaimed, &$secondDurable, $claimCode): void {
        // Between A's resolving read of the api_tokens row and A's
        // conditional usage UPDATE, B re-claims the code: revokes the first
        // durable, mints a second, relinks the code.
        if (! $reclaimed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'token_hash')) {
            $reclaimed = true;

            $exchange = test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
            $exchange->assertCreated();
            $secondDurable = (string) $exchange->json('durable_token');
        }
    });

    // A's authentication must FAIL: the row it read was revoked under it.
    expect($registry->resolve($firstDurable))->toBeNull()
        ->and($reclaimed)->toBeTrue();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();
    $firstRow = ApiToken::query()->where('token_hash', hash('sha256', $firstDurable))->firstOrFail();
    $secondRow = ApiToken::query()->where('token_hash', hash('sha256', (string) $secondDurable))->firstOrFail();

    // The code stays governed by its NEW linkage, unconsumed by A, and the
    // dead row took no usage bump.
    expect($code->consumed_at)->toBeNull()
        ->and($code->durable_token_id)->toBe($secondRow->getKey())
        ->and($firstRow->request_count)->toBe(0)
        ->and($firstRow->last_used_at)->toBeNull();

    // The re-claimed durable still works and burns the code normally.
    expect($registry->resolve((string) $secondDurable))->toBe('toctou@example.test')
        ->and($code->refresh()->consumed_at)->not->toBeNull();
});

it('fails authentication when the durable expires mid-resolution and leaves the code reclaimable', function (): void {
    [$claimCode, $durable] = burnExchange('expiring@example.test');

    $registry = app(TokenRegistry::class);

    $expiredUnderUs = false;

    DB::listen(function (QueryExecuted $query) use (&$expiredUnderUs, $durable): void {
        if (! $expiredUnderUs
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'token_hash')) {
            $expiredUnderUs = true;

            ApiToken::query()
                ->where('token_hash', hash('sha256', $durable))
                ->update(['expires_at' => now()->subSecond()]);
        }
    });

    expect($registry->resolve($durable))->toBeNull()
        ->and($expiredUnderUs)->toBeTrue();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // Unconsumed: the recipient can re-claim the still-live code.
    expect($code->consumed_at)->toBeNull();

    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
});

it('bounds the name+scope sweep to the colliding name and scope', function (): void {
    $differentName = mintApiToken('other@example.test', [Scope::Consume->value]);
    $sameNameDifferentScope = mintApiToken('person@example.test', [Scope::Admin->value]);

    $claimCode = issueOnboardingToken('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $registry = app(TokenRegistry::class);

    expect($registry->resolve($differentName))->toBe('other@example.test')
        ->and($registry->resolve($sameNameDifferentScope))->toBe('person@example.test');
});

it('spares a rotation grace-window row from the name+scope sweep', function (): void {
    $registry = app(TokenRegistry::class);

    $gracePlaintext = mintApiToken('person@example.test', [Scope::Consume->value]);

    // Rotation stamps the outgoing row with the 1h grace expiry and mints a
    // same-name successor — the signal the sweep recognises.
    $registry->rotate('person@example.test', hash('sha256', 'rotated-'.bin2hex(random_bytes(8))));

    $claimCode = issueOnboardingToken('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    // The grace row still resolves for the remainder of its window.
    expect($registry->resolve($gracePlaintext))->toBe('person@example.test');
});

it('never sweeps a durable linked to a different unconsumed code', function (): void {
    // Names are free text: another pending integration's durable can share
    // the name. Craft the collision directly.
    $collidingPlaintext = mintApiToken('person@example.test', [Scope::Consume->value]);
    $collidingRow = ApiToken::query()->where('token_hash', hash('sha256', $collidingPlaintext))->firstOrFail();

    $otherCode = OnboardingToken::query()->create([
        'email' => 'other@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => OnboardingToken::hashToken(bin2hex(random_bytes(32))),
        'durable_token_id' => $collidingRow->getKey(),
        'expires_at' => now()->addHour(),
    ]);

    $claimCode = issueOnboardingToken('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    // The other code's durable survives, governed by its own lifecycle.
    expect(ApiToken::query()->whereKey($collidingRow->getKey())->resolvable()->exists())->toBeTrue()
        ->and($otherCode->refresh()->consumed_at)->toBeNull();
});

it('answers server_error and rolls back when the minter fails mid-exchange', function (): void {
    // The controller is resolved once per route, so the failure toggle must
    // be in place before the FIRST request builds it.
    $minter = new class(app(ApiTokenMinter::class)) implements DurableCredentialMinter
    {
        public bool $fail = false;

        public function __construct(private readonly ApiTokenMinter $inner) {}

        public function mint(string $name, string $scope): MintedDurableCredential
        {
            if ($this->fail) {
                throw new RuntimeException('minting infrastructure unavailable');
            }

            return $this->inner->mint($name, $scope);
        }
    };

    app()->instance(DurableCredentialMinter::class, $minter);

    [$claimCode, $firstDurable] = burnExchange('failure@example.test');

    $minter->fail = true;

    $response = $this->assertNoSecretLeakage($claimCode, function () use ($claimCode): TestResponse {
        return $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    });

    $response->assertStatus(500)
        ->assertExactJson([
            'version' => 1,
            'error' => 'server_error',
            'message' => 'The server hit an unexpected error. It is safe to retry.',
        ]);

    $this->assertResponseCarriesNoSecret($response, $claimCode);
    $this->assertResponseCarriesNoSecret($response, $firstDurable);

    // The whole exchange rolled back: code unconsumed and still linked to
    // the first durable, which is not revoked; nothing new was minted.
    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();
    $firstRow = ApiToken::query()->where('token_hash', hash('sha256', $firstDurable))->firstOrFail();

    expect($code->consumed_at)->toBeNull()
        ->and($code->durable_token_id)->toBe($firstRow->getKey())
        ->and($firstRow->revoked_at)->toBeNull()
        ->and(ApiToken::query()->where('name', 'failure@example.test')->count())->toBe(1);

    // A retry with working infrastructure succeeds.
    $minter->fail = false;
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
});

it('answers server_error when verify hits an unexpected failure', function (): void {
    [, $durable] = burnExchange('verify-failure@example.test');

    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'token_hash')) {
            $armed = false;

            throw new RuntimeException('database unavailable');
        }
    });

    test()->postJson('/bfc/onboarding/verify', [], bearerHeaders($durable))
        ->assertStatus(500)
        ->assertJsonPath('error', 'server_error');
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
