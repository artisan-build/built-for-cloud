<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\MintedDurableCredential;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use RuntimeException;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

it('locks the claim codes before the durable row when burning first use', function (): void {
    // The deadlock-avoidance property is an ORDER property: exchange
    // acquires code-then-durable, and the burn must acquire in the SAME
    // order or two opposing transactions can each hold one lock and wait
    // on the other forever. SQLite compiles lockForUpdate() to nothing,
    // so what is observable here — and what a refactor could silently
    // reorder — is the SEQUENCE of statements the burn issues inside its
    // transaction: the codes read must precede the first durable
    // reference.
    [$claimCode, $durable] = burnExchange('ordered@example.test');

    $queries = [];

    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        $queries[] = $query->sql;
    });

    expect(resolveUnifiedClaimDurable($durable)?->name)->toBe('ordered@example.test');

    // The resolving read — the credentials lookup by secret hash — is the
    // last durable query OUTSIDE the burn's transaction. Everything the
    // burn does follows it, and the order property is: the very next
    // table the burn touches is the CLAIM CODES, and the durable row is
    // only written after them. (RefreshDatabase makes the burn's
    // transaction a nested savepoint whose statements Laravel does not
    // log, so the sequence is anchored on the resolving read instead of
    // a begin marker.)
    $resolvingRead = null;

    foreach ($queries as $index => $sql) {
        if (preg_match('/^\s*select\b/i', $sql) === 1
            && str_contains($sql, 'credentials')
            && str_contains($sql, 'secret_hash')) {
            $resolvingRead = $index;
        }
    }

    expect($resolvingRead)->not->toBeNull('The resolve never read the durable row.');

    $firstCodes = null;

    foreach ($queries as $index => $sql) {
        if ($index > $resolvingRead && str_contains($sql, 'onboarding_tokens')) {
            $firstCodes = $index;

            break;
        }
    }

    expect($firstCodes)->not->toBeNull('The burn never read the claim codes.');

    // No durable reference may come between the resolving read and the
    // codes read — a durable-first acquisition would put one there.
    $between = array_slice($queries, (int) $resolvingRead + 1, (int) $firstCodes - (int) $resolvingRead - 1);

    expect(
        array_filter($between, fn (string $sql): bool => str_contains($sql, 'credentials')),
    )->toBe([]);

    // And the durable write comes only after the codes read.
    $firstDurableWrite = null;

    foreach ($queries as $index => $sql) {
        if ($index > $firstCodes
            && preg_match('/^\s*update\b/i', $sql) === 1
            && str_contains($sql, 'credentials')) {
            $firstDurableWrite = $index;

            break;
        }
    }

    expect($firstDurableWrite)->not->toBeNull('The burn never wrote the durable row.');
});

it('consumes the claim code exactly once when two resolutions race at the affected-rows gate', function (): void {
    [$claimCode, $durable] = burnExchange('race@example.test');

    $consumptionWrites = 0;
    $competitorFired = false;

    DB::listen(function (QueryExecuted $query) use (&$consumptionWrites, &$competitorFired, $durable): void {
        if (preg_match('/^\s*update\b/i', $query->sql) === 1
            && str_contains($query->sql, 'onboarding_tokens')
            && str_contains($query->sql, 'consumed_at')) {
            $consumptionWrites++;
        }

        // Between the loser's read of the credentials row and its
        // conditional UPDATE, the competing process resolves first — so the
        // loser enters the burn with a stale NULL last_used_at, its
        // conditional update affects zero rows, and the gate must stop it
        // consuming.
        if (! $competitorFired
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $competitorFired = true;
            resolveUnifiedClaimDurable($durable);
        }
    });

    expect(resolveUnifiedClaimDurable($durable)?->name)->toBe('race@example.test');

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($competitorFired)->toBeTrue()
        ->and($code->consumed_at)->not->toBeNull()
        ->and($consumptionWrites)->toBe(1);
});

it('leaves the code unconsumed when the process dies between the usage write and the consumption', function (): void {
    [$claimCode, $durable] = burnExchange('death@example.test');

    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*update\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'last_used_at')) {
            $armed = false;

            throw new RuntimeException('simulated process death after the usage write');
        }
    });

    expect(fn (): ?Credential => resolveUnifiedClaimDurable($durable))->toThrow(RuntimeException::class);

    $tokenRow = Credential::query()->where('name', 'death@example.test')->firstOrFail();
    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // BOTH writes rolled back: the code is unconsumed rather than
    // orphaned-unburned, and the token shows no use.
    expect($tokenRow->last_used_at)->toBeNull()
        ->and($code->consumed_at)->toBeNull();

    // A retry then succeeds and burns normally.
    expect(resolveUnifiedClaimDurable($durable)?->name)->toBe('death@example.test')
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

    expect(resolveUnifiedClaimDurable($password)?->name)->toBe('crate@example.test');

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($code->consumed_at)->not->toBeNull();
});

it('does not revoke the live durable at issue and revokes both ways at exchange', function (): void {
    // A working integration: a live durable of the same name+scope, linked
    // to no claim code at all.
    $livePlaintext = mintUnifiedClaimDurable('person@example.test', Scope::Consume);

    expect(resolveUnifiedClaimDurable($livePlaintext)?->name)->toBe('person@example.test');

    $claimCode = auditIssueCode('person@example.test');

    // The code sitting in an inbox breaks nothing on send day.
    expect(resolveUnifiedClaimDurable($livePlaintext)?->name)->toBe('person@example.test');

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    // After exchange: the name+scope revocation caught the unlinked live
    // durable, and exactly one live durable remains — the new one.
    expect(resolveUnifiedClaimDurable($livePlaintext))->toBeNull();

    expect(Credential::query()->where('name', 'person@example.test')->active()->count())->toBe(1)
        ->and(resolveUnifiedClaimDurable((string) $exchange->json('durable_token'))?->name)->toBe('person@example.test');
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

    $claimCode = auditIssueCode('reel@example.test');

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
    expect(resolveUnifiedClaimDurable((string) $exchange->json('durable_token'))?->name)->toBe('reel@example.test');
});

it('fails authentication when the durable is revoked and the code relinked mid-resolution', function (): void {
    [$claimCode, $firstDurable] = burnExchange('toctou@example.test');

    $reclaimed = false;
    $secondDurable = null;

    DB::listen(function (QueryExecuted $query) use (&$reclaimed, &$secondDurable, $claimCode): void {
        // Between A's resolving read of the credentials row and A's
        // conditional usage UPDATE, B re-claims the code: revokes the first
        // durable, mints a second, relinks the code.
        if (! $reclaimed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $reclaimed = true;

            $exchange = test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
            $exchange->assertCreated();
            $secondDurable = (string) $exchange->json('durable_token');
        }
    });

    // A's authentication must FAIL: the row it read was revoked under it.
    expect(resolveUnifiedClaimDurable($firstDurable))->toBeNull()
        ->and($reclaimed)->toBeTrue();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();
    $firstRow = Credential::query()->where('secret_hash', hash('sha256', $firstDurable))->firstOrFail();
    $secondRow = Credential::query()->where('secret_hash', hash('sha256', (string) $secondDurable))->firstOrFail();

    // The code stays governed by its NEW linkage, unconsumed by A, and the
    // dead row took no usage bump.
    expect($code->consumed_at)->toBeNull()
        ->and($code->durable_credential_id)->toBe($secondRow->getKey())
        ->and($firstRow->last_used_at)->toBeNull();

    // The re-claimed durable still works and burns the code normally.
    expect(resolveUnifiedClaimDurable((string) $secondDurable)?->name)->toBe('toctou@example.test')
        ->and($code->refresh()->consumed_at)->not->toBeNull();
});

it('fails authentication when the durable expires mid-resolution and leaves the code reclaimable', function (): void {
    [$claimCode, $durable] = burnExchange('expiring@example.test');

    $expiredUnderUs = false;

    DB::listen(function (QueryExecuted $query) use (&$expiredUnderUs, $durable): void {
        if (! $expiredUnderUs
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $expiredUnderUs = true;

            Credential::query()
                ->where('secret_hash', hash('sha256', $durable))
                ->update(['expires_at' => now()->subSecond()]);
        }
    });

    expect(resolveUnifiedClaimDurable($durable))->toBeNull()
        ->and($expiredUnderUs)->toBeTrue();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    // Unconsumed: the recipient can re-claim the still-live code.
    expect($code->consumed_at)->toBeNull();

    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
});

it('bounds the name+scope sweep to the colliding name and scope', function (): void {
    $differentName = mintUnifiedClaimDurable('other@example.test', Scope::Consume);
    $sameNameDifferentScope = mintUnifiedClaimDurable('person@example.test', Scope::Admin);

    $claimCode = auditIssueCode('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    expect(resolveUnifiedClaimDurable($differentName)?->name)->toBe('other@example.test')
        ->and(resolveUnifiedClaimDurable($sameNameDifferentScope)?->name)->toBe('person@example.test');
});

it('spares a genuinely rotated row from the name+scope sweep', function (): void {
    $gracePlaintext = mintUnifiedClaimDurable('person@example.test', Scope::Consume);
    Credential::query()->where('secret_hash', hash('sha256', $gracePlaintext))->update([
        'rotated_at' => now(),
        'expires_at' => now()->addHour(),
    ]);

    $claimCode = auditIssueCode('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    // The rotated row still resolves for the remainder of its grace window.
    expect(resolveUnifiedClaimDurable($gracePlaintext)?->name)->toBe('person@example.test');
});

it('sweeps a crafted same-name short-TTL token that only mimics rotation', function (): void {
    // The shape the old heuristic spared: a 30-minute-TTL token of the
    // colliding name+scope beside a same-name later row. It carries no
    // rotation provenance, so it must die in the sweep — otherwise TWO live
    // durables survive an exchange.
    $craftedPlaintext = 'crafted-'.bin2hex(random_bytes(8));

    mintUnifiedClaimDurable('person@example.test', Scope::Consume, $craftedPlaintext, now()->addMinutes(30));

    mintUnifiedClaimDurable('person@example.test', Scope::Admin);

    $claimCode = auditIssueCode('person@example.test');
    $exchange = test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    // The crafted token died; the fresh durable is the only live
    // consume-scoped one (at-most-one-live holds).
    expect(resolveUnifiedClaimDurable($craftedPlaintext))->toBeNull()
        ->and(resolveUnifiedClaimDurable((string) $exchange->json('durable_token'))?->name)->toBe('person@example.test');
});

it('stamps rotated_at on the outgoing row for normal and emergency rotation', function (): void {
    $registry = app(TokenRegistry::class);

    $normalPlaintext = mintLegacyBurnToken('normal-rotation', Scope::Consume);
    $registry->rotate('normal-rotation', hash('sha256', 'n-'.bin2hex(random_bytes(8))));

    $emergencyPlaintext = mintLegacyBurnToken('emergency-rotation', Scope::Consume);
    $registry->rotate('emergency-rotation', hash('sha256', 'e-'.bin2hex(random_bytes(8))), emergency: true);

    $normalRow = ApiToken::query()->where('token_hash', hash('sha256', $normalPlaintext))->firstOrFail();
    $emergencyRow = ApiToken::query()->where('token_hash', hash('sha256', $emergencyPlaintext))->firstOrFail();

    expect($normalRow->rotated_at)->not->toBeNull()
        ->and($emergencyRow->rotated_at)->not->toBeNull();
});

it('fails authentication when an already-used durable dies after the resolving read', function (): void {
    [, $durable] = burnExchange('fastpath@example.test');

    // First use burns and sets last_used_at: later resolutions take the
    // fast path.
    expect(resolveUnifiedClaimDurable($durable)?->name)->toBe('fastpath@example.test');

    $died = false;

    DB::listen(function (QueryExecuted $query) use (&$died, $durable): void {
        if (! $died
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $died = true;

            Credential::query()
                ->where('secret_hash', hash('sha256', $durable))
                ->update(['expires_at' => now()->subSecond()]);
        }
    });

    // The fast-path bump carries the resolvability predicate: zero affected
    // rows is an authentication failure, not a silent bump.
    expect(resolveUnifiedClaimDurable($durable))->toBeNull()
        ->and($died)->toBeTrue();

    expect(Credential::query()->where('secret_hash', hash('sha256', $durable))->firstOrFail()->last_used_at)->not->toBeNull();
});

it('fails authentication when the row dies between the first-use gate and the recovery bump', function (): void {
    [$claimCode, $durable] = burnExchange('recovery@example.test');

    $competed = false;
    $killed = false;

    DB::listen(function (QueryExecuted $query) use (&$competed, &$killed, $durable): void {
        // During A's resolving read, another process's usage bump lands:
        // A's first-use conditional will return zero rows.
        if (! $competed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $competed = true;

            Credential::query()
                ->where('secret_hash', hash('sha256', $durable))
                ->update(['last_used_at' => now()]);

            return;
        }

        // Between A's zero-row first-use gate (the update whose WHERE
        // carries `last_used_at IS NULL`) and A's recovery bump, the row
        // dies.
        if ($competed
            && ! $killed
            && preg_match('/^\s*update\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'is null')) {
            $killed = true;

            Credential::query()
                ->where('secret_hash', hash('sha256', $durable))
                ->update(['expires_at' => now()->subSecond()]);
        }
    });

    // The recovery bump re-asserts resolvability and fails: no auth, no
    // bump, and A consumes nothing.
    expect(resolveUnifiedClaimDurable($durable))->toBeNull()
        ->and($competed)->toBeTrue()
        ->and($killed)->toBeTrue();

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($code->consumed_at)->toBeNull();
});

it('never sweeps a durable linked to a different unconsumed code', function (): void {
    // Names are free text: another pending integration's durable can share
    // the name. Craft the collision directly.
    $collidingPlaintext = mintUnifiedClaimDurable('person@example.test', Scope::Consume);
    $collidingRow = Credential::query()->where('secret_hash', hash('sha256', $collidingPlaintext))->firstOrFail();

    $otherCode = OnboardingToken::query()->create([
        'email' => 'other@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => OnboardingToken::hashToken(bin2hex(random_bytes(32))),
        'durable_credential_id' => $collidingRow->getKey(),
        'expires_at' => now()->addHour(),
    ]);

    $claimCode = auditIssueCode('person@example.test');
    test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    // The other code's durable survives, governed by its own lifecycle.
    expect(Credential::query()->whereKey($collidingRow->getKey())->active()->exists())->toBeTrue()
        ->and($otherCode->refresh()->consumed_at)->toBeNull();
});

it('answers server_error and rolls back when the minter fails mid-exchange', function (): void {
    // The controller is resolved once per route, so the failure toggle must
    // be in place before the FIRST request builds it.
    $minter = new class(app(UnifiedStoreCredentialMinter::class)) implements DurableCredentialMinter
    {
        public bool $fail = false;

        public function __construct(private readonly UnifiedStoreCredentialMinter $inner) {}

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
    $firstRow = Credential::query()->where('secret_hash', hash('sha256', $firstDurable))->firstOrFail();

    expect($code->consumed_at)->toBeNull()
        ->and($code->durable_credential_id)->toBe($firstRow->getKey())
        ->and($firstRow->revoked_at)->toBeNull()
        ->and(Credential::query()->where('name', 'failure@example.test')->count())->toBe(1);

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
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'secret_hash')) {
            $armed = false;

            throw new RuntimeException('database unavailable');
        }
    });

    test()->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$durable])
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
    $claimCode = auditIssueCode($email);

    $exchange = test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();

    return [$claimCode, (string) $exchange->json('durable_token')];
}

function resolveUnifiedClaimDurable(string $secret): ?Credential
{
    $credential = app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret);

    if ($credential === null || ! app(CredentialUsageRecorder::class)->recordUsage($credential)) {
        return null;
    }

    return $credential;
}

function mintUnifiedClaimDurable(
    string $name,
    Scope $scope,
    ?string $secret = null,
    mixed $expiresAt = null,
): string {
    $secret ??= 'unified-'.bin2hex(random_bytes(16));

    Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => $name,
        'name' => $name,
        'abilities' => [$scope->value],
        'secret_hash' => hash('sha256', $secret),
        'expires_at' => $expiresAt,
    ]);

    return $secret;
}

function mintLegacyBurnToken(string $name, Scope $scope): string
{
    $secret = 'legacy-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => $name,
        'token_hash' => hash('sha256', $secret),
        'abilities' => [$scope->value],
    ]);

    return $secret;
}
