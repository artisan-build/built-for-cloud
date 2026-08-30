<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * Console countersigning-key custody (Console PRD D12, PR2): how this
 * deployment comes to hold the vendor's per-deployment PUBLIC key — at
 * claim time, and afterwards through the re-key verb that retrofits a
 * fleet which has already claimed.
 *
 * The property every test here defends: **whoever controls a filed key
 * controls who can enter this deployment as an admin.** Every path that
 * writes a keyring row is a takeover path, so the tests are about
 * authority and atomicity at least as much as about mechanics:
 *
 *  1. **Authority is explicit per surface.** An ownership claim carries
 *     it implicitly (its holder is becoming the admin anyway); an
 *     onboarding code carries it only if issued with it; the route
 *     wants `console:key:write`; the CLI's authority is host access and
 *     says so.
 *  2. **Additive.** An envelope that carries no key behaves exactly as
 *     it did before this release, down to its response keys.
 *  3. **Make-before-break.** A re-key activates a new key and retires
 *     nothing; retirement is a separate, later act, and it sticks.
 *  4. **Atomic.** A refused delivery leaves nothing behind — no row, no
 *     burn, no owner token.
 */
beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
        'built-for-cloud.product' => 'Sink',
    ]);

    Queue::fake();
});

// ------------------------------------------------------------- helpers

/**
 * An operator credential holding exactly the abilities named.
 *
 * @param  list<string>|null  $abilities
 * @param  array<string, mixed>  $attributes
 */
function keyCustodyOperator(?array $abilities, array $attributes = []): MintedTestCredential
{
    return test()->mintCredential(array_merge([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'console-'.bin2hex(random_bytes(4)),
        'abilities' => $abilities,
    ], $attributes));
}

/**
 * An operator credential that may write console keys.
 */
function keyCustodyWriter(): MintedTestCredential
{
    return keyCustodyOperator([OperatorAbility::ConsoleKeyWrite->value]);
}

/**
 * A pending ownership claim code, ready to present.
 */
function keyCustodyClaimCode(string $plaintext = 'console-claim'): string
{
    OwnershipClaim::query()->create(['token_hash' => OwnershipClaim::hashToken($plaintext)]);

    return $plaintext;
}

/**
 * Claim the deployment with no key, the way a fleet that predates this
 * feature is already claimed. Every re-key test needs this: an unclaimed
 * deployment refuses to be keyed at all (rework A6).
 */
function keyCustodyClaimedDeployment(): string
{
    $response = test()->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode('owner-'.bin2hex(random_bytes(6))),
    ]);

    $response->assertCreated();

    return (string) $response->json('owner_token');
}

/**
 * A fresh onboarding claim code, issued through the real verb.
 *
 * `$keyAuthority` is what the issuing operator decides: without it the
 * code cannot deliver a console key at all (rework B1).
 *
 * Local rather than borrowed from another test file so this suite runs
 * standalone under a `--filter`, which is the convention `tests/Pest.php`
 * states for shared helpers.
 */
function keyCustodyOnboardingCode(string $email = 'console@example.test', bool $keyAuthority = false): string
{
    $plaintext = 'admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'console-issuer-'.bin2hex(random_bytes(4)),
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    $response = test()->postJson('/bfc/onboarding/issue', [
        'email' => $email,
        'scope' => Scope::Consume->value,
        'ttl_seconds' => 3600,
        'console_key_authority' => $keyAuthority,
    ], ['Authorization' => 'Bearer '.$plaintext]);

    $response->assertCreated();

    return (string) $response->json('claim_code');
}

/**
 * The public half of a fresh vendor keypair, in the hex form a real
 * delivery carries. Every call yields DIFFERENT material on purpose:
 * material is unique per deployment now (rework B4), so a test that
 * reused one key across key ids would be testing that rule by accident.
 */
function keyCustodyPublicKey(?AsymmetricSecretKey $secret = null): string
{
    return ($secret ?? consoleKeypair())->getPublicKey()->toHexString();
}

/**
 * Run the CLI verb with key material on its INPUT STREAM, which is what
 * the command reads instead of argv (rework B3).
 *
 * Driven through `Command::run()` with a memory stream rather than
 * Laravel's `artisan()` helper, because `artisan()` gives the command no
 * stream and it would fall back to the test runner's own STDIN.
 *
 * @return array{int, string} exit status and captured output
 */
function keyCustodyRunCli(string $keyId, ?string $publicKey, bool $local = true): array
{
    $command = app(ConsoleReKeyCommand::class);
    $command->setLaravel(app());

    $parameters = ['key_id' => $keyId];

    if ($local) {
        $parameters['--local'] = true;
    }

    $stream = fopen('php://memory', 'r+');

    if ($publicKey !== null) {
        fwrite($stream, $publicKey."\n");
    }

    rewind($stream);

    $input = new ArrayInput($parameters);
    $input->setStream($stream);

    $output = new BufferedOutput;
    $status = $command->run($input, $output);

    fclose($stream);

    return [$status, $output->fetch()];
}

/**
 * Bind a declaration that burns the claim code AT EXCHANGE, so a test
 * can observe whether a refused exchange left the code presentable.
 */
function keyCustodyBurnAtExchange(): void
{
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
}

/**
 * Every key id verifying right now, sorted.
 *
 * @return list<string>
 */
function keyCustodyActiveIds(): array
{
    return array_map(
        static fn (ConsoleKey $key): string => $key->key_id,
        (new ConsoleKeyring)->active(),
    );
}

/**
 * Material this deployment must never file. Each entry is a shape PR1's
 * keyring refuses, and the point of driving them THROUGH the delivery
 * surfaces is to prove the surfaces route into that keyring rather than
 * writing their own, laxer, check.
 *
 * @return array<string, string>
 */
function keyCustodyRejectedMaterial(): array
{
    return [
        'empty' => '',
        'not an encoding' => 'not-a-key',
        'a PEM blob' => '-----BEGIN PUBLIC KEY-----',
        'sixteen bytes' => bin2hex(random_bytes(16)),
        'one byte short' => bin2hex(random_bytes(31)),
        'one byte long' => bin2hex(random_bytes(33)),
        // Fixed, not random: roughly one random 32-byte string in twenty
        // IS a valid curve point, so a random fixture would flake.
        'thirty-two bytes that are not a curve point' => str_repeat('00', 32),
    ];
}

// --------------------------------------------- AC1 — claim-time filing

it('files the delivered public key on the ownership claim and reports the key id (AC1)', function (): void {
    $secret = consoleKeypair();
    $public = keyCustodyPublicKey($secret);

    $response = $this->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode(),
        'console_key' => ['key_id' => 'k1', 'public_key' => $public],
    ]);

    $response->assertCreated()
        ->assertJsonPath('console_key.key_id', 'k1')
        ->assertJsonPath('console_key.status', 'active')
        ->assertJsonPath('console_key.active_key_ids', ['k1'])
        ->assertJsonStructure(['owner_token', 'webhook_secret', 'product', 'console_key' => ['activated_at']]);

    $key = ConsoleKey::query()->sole();

    expect($key->key_id)->toBe('k1')
        ->and($key->public_key)->toBe($public)
        ->and($key->activated_at)->not->toBeNull()
        ->and($key->retired_at)->toBeNull();

    // Filed AND trusted: an assertion signed by it verifies immediately.
    expect(consoleVerify(consoleMint($secret, consoleClaims(), 'k1'))->keyId)->toBe('k1');
});

it('files the delivered public key on an AUTHORIZED onboarding exchange and reports the key id (AC1)', function (): void {
    keyCustodyClaimedDeployment();

    $secret = consoleKeypair();
    $public = keyCustodyPublicKey($secret);

    $response = $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('console@example.test', keyAuthority: true),
        'console_key' => ['key_id' => 'k1', 'public_key' => $public],
    ]);

    $response->assertCreated()
        ->assertJsonPath('console_key.key_id', 'k1')
        ->assertJsonPath('console_key.status', 'active')
        ->assertJsonStructure(['durable_token', 'name', 'console_key']);

    expect(ConsoleKey::query()->sole()->public_key)->toBe($public)
        ->and(consoleVerify(consoleMint($secret, consoleClaims(), 'k1'))->keyId)->toBe('k1');
});

// ------------------------------------------ AC2 — backward compatibility

it('leaves both claim envelopes and the issue verb byte-identical when no key is involved (AC2)', function (): void {
    // The ownership claim: the pre-console response shape, EXACTLY —
    // three keys, no `console_key` at all (absent, not null).
    $claim = $this->postJson('/bfc/ownership/claim', ['token' => keyCustodyClaimCode()]);

    $claim->assertCreated();

    expect(array_keys((array) $claim->json()))->toBe(['owner_token', 'webhook_secret', 'product'])
        ->and($claim->json('product'))->toBe('Sink');

    // And the claim did everything it always did: ownership is held by
    // an owner token that works.
    $ownership = Ownership::current();

    expect($ownership?->owner_token_id)->not->toBeNull();

    // The onboarding exchange: likewise exactly two keys.
    $exchange = $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('plain@example.test'),
    ]);

    $exchange->assertCreated();

    expect(array_keys((array) $exchange->json()))->toBe(['durable_token', 'name'])
        ->and($exchange->json('name'))->toBe('plain@example.test');

    // Nothing was filed, and nothing pretended to be.
    expect(ConsoleKey::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->where('note', 'like', 'console%')->count())->toBe(0);
});

it('leaves the issue response unchanged unless key-custody authority was granted (AC2)', function (): void {
    $plaintext = 'admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'issuer',
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    $plain = $this->postJson('/bfc/onboarding/issue', [
        'email' => 'a@b.test',
        'ttl_seconds' => 3600,
    ], ['Authorization' => 'Bearer '.$plaintext]);

    $plain->assertCreated();

    expect(array_keys((array) $plain->json()))->toBe(['claim_code', 'email']);

    $granted = $this->postJson('/bfc/onboarding/issue', [
        'email' => 'c@d.test',
        'ttl_seconds' => 3600,
        'console_key_authority' => true,
    ], ['Authorization' => 'Bearer '.$plaintext]);

    $granted->assertCreated()->assertJsonPath('console_key_authority', true);
});

it('treats an explicit console_key null as absence, not as a delivery (AC2, J3)', function (): void {
    // Documented in ConsoleKeyDelivery::optionalFrom and previously
    // unexercised: null is "no key", NOT a half-filled object.
    $claim = $this->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode(),
        'console_key' => null,
    ]);

    $claim->assertCreated();

    expect(array_keys((array) $claim->json()))->toBe(['owner_token', 'webhook_secret', 'product']);

    // Same on the exchange, and note the code carries NO key authority:
    // a null delivery must not even be read as an attempt, or this would
    // refuse.
    $exchange = $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('null@example.test'),
        'console_key' => null,
    ]);

    $exchange->assertCreated();

    expect(array_keys((array) $exchange->json()))->toBe(['durable_token', 'name'])
        ->and(ConsoleKey::query()->count())->toBe(0);
});

// --------------------------------- AC13 — claim codes need the authority

it('refuses a console key delivered on a code with no key-custody authority (AC13)', function (): void {
    keyCustodyClaimedDeployment();

    // The routine code an operator hands a low-privilege integration.
    $code = keyCustodyOnboardingCode('integration@example.test', keyAuthority: false);

    $refusal = $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey()],
    ]);

    // 403: the caller presented a perfectly good code; it just does not
    // carry this authority.
    $refusal->assertStatus(403)->assertJsonStructure(['message']);

    $row = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole();

    // The WHOLE exchange rolled back — the check runs before the burn
    // and before the mint, so an unauthorized attempt costs nothing.
    expect(ConsoleKey::query()->count())->toBe(0)
        ->and($row->consumed_at)->toBeNull()
        ->and($row->durable_token_id)->toBeNull()
        ->and($row->console_key_filed_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(0);

    // And the code still works for what it WAS issued to do.
    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();
});

it('spends key-custody authority on the first key and refuses a second (AC13)', function (): void {
    // DELIBERATELY the default `first_use` burn mode, and an earlier
    // revision of this test got that wrong in a way worth recording: it
    // bound `at_exchange`, so the second exchange died on the code's own
    // `consumed_at` check and answered `code_already_claimed` without
    // ever reaching the authority check this test exists to drive. The
    // assertion accepted either status, so it passed while proving
    // nothing — and a mutant reading `console_key_authority` instead of
    // `mayFileConsoleKey()` survived it.
    //
    // `first_use` is also the mode that makes the bug real: the code
    // stays presentable until the durable it minted is first used, so
    // without the spend stamp ONE authorized code files unlimited
    // console keys, each an independent standing admin-entry authority.
    keyCustodyClaimedDeployment();

    $code = keyCustodyOnboardingCode('once@example.test', keyAuthority: true);

    $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey()],
    ])->assertCreated();

    $row = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole();

    expect($row->console_key_filed_at)->not->toBeNull()
        ->and($row->mayFileConsoleKey())->toBeFalse();

    // The code is still presentable — nothing has burned it — so this
    // reaches the authority check, which is the point.
    expect($row->consumed_at)->toBeNull();

    $second = $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k2', 'public_key' => keyCustodyPublicKey()],
    ]);

    // Exactly 403, and exactly the NotAuthorized prose: a 409 here would
    // mean the code was refused for being spent as a CLAIM CODE rather
    // than for having spent its KEY-CUSTODY AUTHORITY, which is a
    // different rule and not the one under test.
    $second->assertStatus(403)
        ->assertJsonPath('message', ConsoleKeyRefusal::NotAuthorized->message());

    expect(ConsoleKey::query()->count())->toBe(1)
        ->and(ConsoleKey::query()->sole()->key_id)->toBe('k1');
});

it('cannot be granted key-custody authority through mass assignment (AC13)', function (): void {
    // The flag is not fillable, so nothing a request body reaches can
    // set it — the same discipline api_tokens.rotated_at uses.
    $token = OnboardingToken::query()->create([
        'email' => 'forged@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => OnboardingToken::hashToken('forged'),
        'expires_at' => now()->addHour(),
        'console_key_authority' => true,
        'console_key_filed_at' => null,
    ]);

    expect($token->refresh()->console_key_authority)->toBeFalse()
        ->and($token->mayFileConsoleKey())->toBeFalse();
});

// ------------------------------------------------ AC3 — refused material

it('refuses key material the keyring will not store and files nothing (AC3)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $shape = 0;

    foreach (keyCustodyRejectedMaterial() as $description => $material) {
        $shape++;

        // Through the re-key verb…
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k'.$shape, 'public_key' => $material], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertStatus(422);

        // …and through an AUTHORIZED claim code, which is the half that
        // proves the claim surface routes into PR1's keyring rather than
        // carrying its own, laxer, check.
        $code = keyCustodyOnboardingCode('shape'.$shape.'@example.test', keyAuthority: true);

        $this->postJson('/bfc/onboarding/exchange', [
            'token' => $code,
            'console_key' => ['key_id' => 'k'.$shape, 'public_key' => $material],
        ])->assertStatus(422);

        expect(ConsoleKey::query()->count())->toBe(0);

        // Fail-closed AND atomic: the code was not spent, so the
        // delivery can be retried once it is fixed.
        $row = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole();

        expect($row->consumed_at)->toBeNull()
            ->and($row->mayFileConsoleKey())->toBeTrue();
    }
});

it('refuses a malformed key id on the same terms as malformed material (AC3)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();

    // NOT in this list: a trailing newline. Laravel's global TrimStrings
    // middleware strips it before any package code runs, so over HTTP
    // "k1\n" simply IS "k1" and files legitimately. The ring's own `\z`
    // anchor is what refuses it where trimming does not happen — the CLI
    // case below drives exactly that.
    foreach (['', 'has spaces', str_repeat('k', 65), 'k/1', 'k 1'] as $keyId) {
        $this->postJson('/bfc/console/re-key', ['key_id' => $keyId, 'public_key' => keyCustodyPublicKey()], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertStatus(422);
    }

    // The untrimmed transport: the stream reaches the ring as sent.
    [$status] = keyCustodyRunCli("k1\n", keyCustodyPublicKey());

    expect($status)->toBe(1)
        ->and(ConsoleKey::query()->count())->toBe(0);
});

it('refuses a half-filled console_key object rather than reading it as absence (AC3)', function (): void {
    $public = keyCustodyPublicKey();

    foreach ([['key_id' => 'k1'], ['public_key' => $public], ['key_id' => 'k1', 'public_key' => 42], 'k1'] as $payload) {
        $this->postJson('/bfc/ownership/claim', [
            'token' => keyCustodyClaimCode('claim-'.md5(serialize($payload))),
            'console_key' => $payload,
        ])->assertStatus(422);
    }

    expect(ConsoleKey::query()->count())->toBe(0)
        ->and(Ownership::current()?->owner_token_id)->toBeNull();
});

// --------------------- J2 — the in-transaction rollback, driven for real

it('rolls the ownership claim back when the delivered key id is already on file (J2)', function (): void {
    // The ONE refusal that reaches the in-transaction throw: everything
    // shape-related refuses before the transaction opens, so only this
    // exercises performClaim's rollback and its actor plumbing.
    keyCustodyClaimedDeployment();
    keyCustodyRunCli('k1', keyCustodyPublicKey());

    expect(ConsoleKey::query()->count())->toBe(1);

    // A SECOND deployment claim (a transfer) that re-uses `k1`.
    $owner = Ownership::current();
    $ownerTokenBefore = $owner?->owner_token_id;

    $release = $this->postJson('/bfc/ownership/release', [], [
        'Authorization' => 'Bearer '.keyCustodyAdminToken(),
    ]);

    $release->assertCreated();

    $successorCode = (string) $release->json('ownership_claim_code');

    $refusal = $this->postJson('/bfc/ownership/claim', [
        'token' => $successorCode,
        'console_key' => ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey()],
    ]);

    $refusal->assertStatus(409)->assertJsonStructure(['message']);

    // Rolled back whole: the successor did not take ownership, the
    // successor's single-use code is unconsumed and still presentable,
    // and no second keyring row exists.
    expect(Ownership::current()?->owner_token_id)->toBe($ownerTokenBefore)
        ->and(OwnershipClaim::query()->whereNull('consumed_at')->count())->toBe(1)
        ->and(ConsoleKey::query()->count())->toBe(1);

    // The refusal was audited against the party that presented the code.
    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($denied->actor_ref)->not->toBeNull()
        ->and((string) $denied->note)->toContain('console_key_id_in_use');

    // …and the successor code still works once the delivery is fixed.
    $this->postJson('/bfc/ownership/claim', ['token' => $successorCode])->assertCreated();
});

it('rolls an at-exchange onboarding exchange back when the key id is already on file (J2)', function (): void {
    keyCustodyBurnAtExchange();
    keyCustodyClaimedDeployment();
    keyCustodyRunCli('k1', keyCustodyPublicKey());

    $code = keyCustodyOnboardingCode('rollback@example.test', keyAuthority: true);

    // `k1` is taken, so this refuses INSIDE the locked transaction —
    // after the burn would have run under AtExchange, and after the
    // durable mint. Both must be undone.
    $refusal = $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey()],
    ]);

    $refusal->assertStatus(409)->assertJsonStructure(['message']);

    $row = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole();

    expect($row->consumed_at)->toBeNull()
        ->and($row->durable_token_id)->toBeNull()
        ->and($row->console_key_filed_at)->toBeNull()
        ->and(ConsoleKey::query()->count())->toBe(1)
        // No durable survived the rollback either.
        ->and(ApiToken::query()->where('name', 'rollback@example.test')->count())->toBe(0);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($denied->actor_ref)->toBe($row->id);

    // …and the code is still good for a fixed delivery.
    $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k2', 'public_key' => keyCustodyPublicKey()],
    ])->assertCreated();
});

/**
 * A legacy admin `api_tokens` row's plaintext. The ownership RELEASE
 * verb wants an admin token and does not care which one, so this mints
 * a fresh one rather than pretending to have kept the owner token's
 * single reveal.
 */
function keyCustodyAdminToken(): string
{
    $plaintext = 'admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'admin-'.bin2hex(random_bytes(4)),
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    return $plaintext;
}

// ----------------------------------------- AC4 — re-key, make-before-break

it('re-keys an already-claimed deployment without re-onboarding and without retiring (AC4)', function (): void {
    // A deployment that claimed BEFORE this feature existed: no key.
    keyCustodyClaimedDeployment();

    $ownershipBefore = Ownership::current();
    $ownerTokenBefore = $ownershipBefore?->owner_token_id;

    expect($ownerTokenBefore)->not->toBeNull();

    $writer = keyCustodyWriter();

    // The retrofit: the first key arrives on a live, claimed deployment.
    $first = consoleKeypair();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey($first),
    ], ['Authorization' => $writer->bearerHeader()])
        ->assertCreated()
        ->assertJsonPath('console_key.key_id', 'k1')
        ->assertJsonPath('console_key.active_key_ids', ['k1']);

    // The rotation: a SECOND key, delivered while the first is live.
    $second = consoleKeypair();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k2',
        'public_key' => keyCustodyPublicKey($second),
    ], ['Authorization' => $writer->bearerHeader()])
        ->assertCreated()
        ->assertJsonPath('console_key.key_id', 'k2')
        // The overlap, reported rather than inferred.
        ->assertJsonPath('console_key.active_key_ids', ['k1', 'k2']);

    // Nothing was retired, and BOTH keys verify — the property that makes
    // this safe to run against a deployment serving traffic.
    expect(ConsoleKey::query()->whereNotNull('retired_at')->count())->toBe(0)
        ->and(keyCustodyActiveIds())->toBe(['k1', 'k2'])
        ->and(consoleVerify(consoleMint($first, consoleClaims(), 'k1'))->keyId)->toBe('k1')
        ->and(consoleVerify(consoleMint($second, consoleClaims(), 'k2'))->keyId)->toBe('k2');

    // No re-onboarding happened: the SAME ownership row, the same owner
    // token id — compared against a value asserted non-null above, so
    // this cannot pass by both sides being null.
    expect(Ownership::current()?->owner_token_id)->toBe($ownerTokenBefore)
        ->and(Ownership::query()->count())->toBe(1)
        // No fresh onboarding code was minted or consumed to do it.
        ->and(OnboardingToken::query()->count())->toBe(0);
});

// ----------------------------------------- AC5 — retirement is separate

it('keeps retirement a separate operation that ends only the retired key (AC5)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $first = consoleKeypair();
    $second = consoleKeypair();

    foreach ([['k1', $first], ['k2', $second]] as [$keyId, $secret]) {
        $this->postJson('/bfc/console/re-key', [
            'key_id' => $keyId,
            'public_key' => keyCustodyPublicKey($secret),
        ], ['Authorization' => $writer->bearerHeader()])->assertCreated();
    }

    // Retirement is a SEPARATE operation, deliberately not something the
    // re-key verb does — it has its own verb and its own tests
    // (`tests/ConsoleKeyRetirementTest.php`). Driven here through the
    // primitive, because what this test is about is that filing retires
    // nothing and that a retirement ends exactly one key.
    (new ConsoleKeyring)->retire('k1');

    expect(keyCustodyActiveIds())->toBe(['k2'])
        ->and(consoleRefusal(consoleMint($first, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey)
        ->and(consoleVerify(consoleMint($second, consoleClaims(), 'k2'))->keyId)->toBe('k2');
});

// ------------------------------------- AC16 — retirement cannot be undone

it('refuses to re-file a retired key\'s material under a new key id (AC16)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $retired = consoleKeypair();
    $retiredPublic = keyCustodyPublicKey($retired);

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $retiredPublic], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertCreated();

    (new ConsoleKeyring)->retire('k1');

    expect(consoleRefusal(consoleMint($retired, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey);

    // Retirement is the ONLY revocation this design has. Re-filing the
    // same bytes under a fresh key id would undo it outright.
    $refusal = $this->postJson('/bfc/console/re-key', ['key_id' => 'k2', 'public_key' => $retiredPublic], [
        'Authorization' => $writer->bearerHeader(),
    ]);

    $refusal->assertStatus(409)->assertJsonStructure(['message']);

    // Same refusal through the claim envelope and the CLI — the rule
    // lives in the shared action, not in one surface.
    $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('retired@example.test', keyAuthority: true),
        'console_key' => ['key_id' => 'k3', 'public_key' => $retiredPublic],
    ])->assertStatus(409);

    [$cliStatus] = keyCustodyRunCli('k4', $retiredPublic);

    expect($cliStatus)->toBe(1);

    // The retired key is still retired, and nothing new verifies.
    $row = ConsoleKey::query()->sole();

    expect($row->key_id)->toBe('k1')
        ->and($row->retired_at)->not->toBeNull()
        ->and(keyCustodyActiveIds())->toBe([])
        ->and(consoleRefusal(consoleMint($retired, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey);
});

// -------------------------- AC6 / AC14 / AC17 — the gate and its refusals

it('gates the re-key verb on its own console:key:write ability (AC14)', function (): void {
    keyCustodyClaimedDeployment();

    $body = fn (): array => ['key_id' => 'k'.bin2hex(random_bytes(2)), 'public_key' => keyCustodyPublicKey()];

    // THE finding: a rotate-scoped credential must NOT reach this verb.
    // Folding console keys into the rotate family would have handed
    // Console-admin takeover to every such credential already issued.
    $rotator = keyCustodyOperator([OperatorAbility::CredentialRotate->value]);

    $this->postJson('/bfc/console/re-key', $body(), ['Authorization' => $rotator->bearerHeader()])
        ->assertStatus(UniformConsoleKeyRefusal::STATUS);

    expect(ConsoleKey::query()->count())->toBe(0);

    // Every other narrow family is refused too.
    foreach ([
        OperatorAbility::CredentialRead,
        OperatorAbility::CredentialMint,
        OperatorAbility::CredentialRevoke,
        OperatorAbility::SubjectOffboard,
        OperatorAbility::AuditRead,
        OperatorAbility::McpAdmin,
    ] as $ability) {
        $narrow = keyCustodyOperator([$ability->value]);

        $this->postJson('/bfc/console/re-key', $body(), ['Authorization' => $narrow->bearerHeader()])
            ->assertStatus(UniformConsoleKeyRefusal::STATUS);
    }

    expect(ConsoleKey::query()->count())->toBe(0);

    // The dedicated ability works…
    $this->postJson('/bfc/console/re-key', ['key_id' => 'writer', 'public_key' => keyCustodyPublicKey()], [
        'Authorization' => keyCustodyWriter()->bearerHeader(),
    ])->assertCreated();

    // …and so does the explicit break-glass, which is a marking an
    // operator chose rather than a family that widened under them.
    $breakGlass = keyCustodyOperator([OperatorAbility::ADMIN]);

    $this->postJson('/bfc/console/re-key', ['key_id' => 'break-glass', 'public_key' => keyCustodyPublicKey()], [
        'Authorization' => $breakGlass->bearerHeader(),
    ])->assertCreated();

    // …and a legacy admin token, as on every operator surface.
    $adminPlaintext = 'legacy-admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'legacy-admin',
        'token_hash' => hash('sha256', $adminPlaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    $this->postJson('/bfc/console/re-key', ['key_id' => 'legacy', 'public_key' => keyCustodyPublicKey()], [
        'Authorization' => 'Bearer '.$adminPlaintext,
    ])->assertCreated();

    expect(ConsoleKey::query()->count())->toBe(3);
});

it('answers every pre-authorization failure with one identical refusal (AC6, AC17)', function (): void {
    keyCustodyClaimedDeployment();

    $body = ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey()];

    $anonymous = $this->postJson('/bfc/console/re-key', $body);
    $unknown = $this->postJson('/bfc/console/re-key', $body, ['Authorization' => 'Bearer '.bin2hex(random_bytes(32))]);

    $lacking = $this->postJson('/bfc/console/re-key', $body, [
        'Authorization' => keyCustodyOperator([OperatorAbility::CredentialRead->value])->bearerHeader(),
    ]);

    $bare = $this->postJson('/bfc/console/re-key', $body, [
        'Authorization' => keyCustodyOperator(null)->bearerHeader(),
    ]);

    $expired = $this->postJson('/bfc/console/re-key', $body, [
        'Authorization' => keyCustodyOperator([OperatorAbility::ConsoleKeyWrite->value], ['expires_at' => now()->subMinute()])->bearerHeader(),
    ]);

    $revoked = $this->postJson('/bfc/console/re-key', $body, [
        'Authorization' => keyCustodyOperator([OperatorAbility::ConsoleKeyWrite->value], ['revoked_at' => now()])->bearerHeader(),
    ]);

    // ALL of them, byte for byte and status for status — including the
    // ability failure, which every OTHER operator route answers as a
    // distinguishable 403 (rework A5). Here the split would tell a
    // caller holding a stale bearer whether it is the credential that
    // can take the deployment.
    foreach ([$unknown, $lacking, $bare, $expired, $revoked] as $refusal) {
        expect($refusal->getStatusCode())->toBe($anonymous->getStatusCode())
            ->and($refusal->getContent())->toBe($anonymous->getContent());
    }

    expect($anonymous->getStatusCode())->toBe(UniformConsoleKeyRefusal::STATUS)
        ->and($anonymous->json('message'))->toBe(UniformConsoleKeyRefusal::MESSAGE)
        ->and(ConsoleKey::query()->count())->toBe(0);

    // The distinction survives INTERNALLY: the gate still records which
    // failure each one was.
    $notes = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->pluck('note')
        ->map(static fn (mixed $note): string => (string) $note)
        ->all();

    expect(collect($notes)->filter(static fn (string $n): bool => str_contains($n, 'token_auth_failure'))->count())->toBeGreaterThan(0)
        ->and(collect($notes)->filter(static fn (string $n): bool => str_contains($n, 'lacks console:key:write'))->count())->toBeGreaterThan(0);
});

// -------------------------------------- AC18 — an unclaimed deployment

it('refuses to key a deployment nobody owns (AC18)', function (): void {
    // The installer mints an operator credential from the HOST, before
    // and independently of any ownership claim — which is why the gate
    // alone never proved "already claimed".
    $writer = keyCustodyWriter();

    expect(Ownership::current()?->owner_token_id)->toBeNull();

    $refusal = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => $writer->bearerHeader()]);

    $refusal->assertStatus(409)->assertJsonStructure(['message']);

    // The CLI is refused on the same rule — host access does not make a
    // deployment owned.
    [$cliStatus] = keyCustodyRunCli('k1', keyCustodyPublicKey());

    expect($cliStatus)->toBe(1)
        ->and(ConsoleKey::query()->count())->toBe(0);

    // Once claimed, the same request works.
    keyCustodyClaimedDeployment();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => $writer->bearerHeader()])->assertCreated();
});

// ------------------------------------------------------- AC7 — the audit

it('audits a successful re-key and a refused one with the actor typed (AC7)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $public = keyCustodyPublicKey();

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertCreated();

    $filed = CredentialAuditEvent::query()->where('event', LifecycleEventType::Delivered->value)->sole();
    $activated = CredentialAuditEvent::query()->where('event', LifecycleEventType::Activated->value)->sole();

    foreach ([$filed, $activated] as $event) {
        expect($event->actor_type)->toBe(AuditActorType::OperatorIntegration)
            ->and($event->actor_ref)->toBe($writer->credential->id)
            ->and((string) $event->note)->toContain('k1')
            // Ids only: the delivered material never reaches the stream.
            ->and((string) $event->note)->not->toContain($public);
    }

    expect((string) $activated->note)->toContain('keys now verifying: k1');

    // A refused re-key — same key id, different material — is audited too.
    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => $writer->bearerHeader()])->assertStatus(409);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console countersigning%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied->actor_ref)->toBe($writer->credential->id)
        ->and((string) $denied->note)->toContain('console_key_id_in_use')
        ->and((string) $denied->note)->toContain('key id k1');
});

it('keeps a hostile key id out of the audit note (AC7)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => "k1\nfabricated: audit line",
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => $writer->bearerHeader()])->assertStatus(422);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console countersigning%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and((string) $denied->note)->toContain('invalid_key_material')
        ->and((string) $denied->note)->not->toContain('fabricated');
});

it('audits a REFUSED cli re-key as cli_operator (AC15, J3)', function (): void {
    keyCustodyClaimedDeployment();
    keyCustodyRunCli('k1', keyCustodyPublicKey());

    // Same key id again: the refusal path, on the transport whose
    // refusal audit was previously static-only.
    [$status] = keyCustodyRunCli('k1', keyCustodyPublicKey());

    expect($status)->toBe(1);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console countersigning%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::CliOperator)
        ->and($denied->actor_ref)->toBeNull()
        ->and((string) $denied->note)->toContain('console_key_id_in_use')
        ->and((string) $denied->note)->toContain('key id k1');
});

// -------------------------------------------------- AC8 — rate limiting

it('rate-limits the re-key verb as an operator write (AC8)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $public = keyCustodyPublicKey();

    // The first delivery files; every repeat is a clean 409 — and each
    // one still spends limiter budget, because the throttle runs BEFORE
    // the gate and the controller.
    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertCreated();

    for ($i = 2; $i <= 60; $i++) {
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertStatus(409);
    }

    $throttled = $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $writer->bearerHeader(),
    ]);

    // 429 stays 429: the uniform-refusal middleware sits INSIDE the
    // throttle, so a rate limit never disguises itself as a refusal.
    $throttled->assertStatus(429);

    // Bounded across addresses too: the per-credential bucket is the one
    // that makes a stolen credential bounded wherever it is replayed.
    $this->withServerVariables(['REMOTE_ADDR' => '10.9.9.9'])
        ->postJson('/bfc/console/re-key', ['key_id' => 'k2', 'public_key' => $public], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertStatus(429);

    expect(ConsoleKey::query()->count())->toBe(1);
});

// ---------------------------------------------------- AC9 — two transports

it('produces identical EFFECTS over HTTP and the artisan verb, with different authority (AC9)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();

    // Parity here means identical EFFECTS for a caller each transport
    // has authorized — NOT identical authorization. The HTTP leg proves
    // a `console:key:write` credential; the CLI leg proves host access
    // and nothing else (rework B3). The material differs per leg because
    // material is unique per deployment.
    $httpSecret = consoleKeypair();
    $cliSecret = consoleKeypair();

    $http = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'parity-http',
        'public_key' => keyCustodyPublicKey($httpSecret),
    ], ['Authorization' => $writer->bearerHeader()]);

    $http->assertCreated();

    [$cliStatus, $cliOutput] = keyCustodyRunCli('parity-cli', keyCustodyPublicKey($cliSecret));

    expect($cliStatus)->toBe(0);

    $viaHttp = ConsoleKey::query()->where('key_id', 'parity-http')->sole();
    $viaCli = ConsoleKey::query()->where('key_id', 'parity-cli')->sole();

    // Same lifecycle state, both trusted, both verifying.
    expect($viaCli->activated_at)->not->toBeNull()
        ->and($viaCli->retired_at)->toBeNull()
        ->and($viaHttp->retired_at)->toBeNull()
        ->and(keyCustodyActiveIds())->toBe(['parity-cli', 'parity-http'])
        ->and(consoleVerify(consoleMint($httpSecret, consoleClaims(), 'parity-http'))->keyId)->toBe('parity-http')
        ->and(consoleVerify(consoleMint($cliSecret, consoleClaims(), 'parity-cli'))->keyId)->toBe('parity-cli');

    // Same events; the actor is the one honest difference, and the CLI
    // output says so in the operator's transcript.
    foreach ([LifecycleEventType::Delivered, LifecycleEventType::Activated] as $event) {
        $actors = CredentialAuditEvent::query()
            ->where('event', $event->value)
            ->orderBy('note')
            ->pluck('actor_type')
            ->all();

        expect($actors)->toHaveCount(2)
            ->and($actors)->toContain(AuditActorType::OperatorIntegration)
            ->and($actors)->toContain(AuditActorType::CliOperator);
    }

    expect($cliOutput)->toContain('HOST ACCESS')
        ->and($cliOutput)->toContain(OperatorAbility::ConsoleKeyWrite->value);

    // Refusal parity: each transport refuses the other's key id with the
    // same server-authored message. Asserted against a non-empty string
    // so a dropped `message` cannot make this pass vacuously.
    $httpRefusal = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'parity-cli',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => $writer->bearerHeader()]);

    $httpRefusal->assertStatus(409);

    $sharedMessage = (string) $httpRefusal->json('message');

    expect($sharedMessage)->not->toBe('');

    [$cliRefusalStatus, $cliRefusalOutput] = keyCustodyRunCli('parity-http', keyCustodyPublicKey());

    expect($cliRefusalStatus)->toBe(1)
        ->and($cliRefusalOutput)->toContain($sharedMessage);

    // …and refuse the same bad material with the same message.
    $httpInvalid = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'parity-new',
        'public_key' => 'not-a-key',
    ], ['Authorization' => $writer->bearerHeader()]);

    $httpInvalid->assertStatus(422);

    $invalidMessage = (string) $httpInvalid->json('message');

    expect($invalidMessage)->not->toBe('');

    [$cliInvalidStatus, $cliInvalidOutput] = keyCustodyRunCli('parity-new', 'not-a-key');

    expect($cliInvalidStatus)->toBe(1)
        ->and($cliInvalidOutput)->toContain($invalidMessage);

    // Neither refusal filed anything.
    expect(ConsoleKey::query()->count())->toBe(2);
});

it('takes key material on stdin and not on argv (AC15)', function (): void {
    keyCustodyClaimedDeployment();

    // Structural: there is no argument to leak into shell history or
    // `ps` output. A key id alone is not a substitution recipe.
    $definition = app(ConsoleReKeyCommand::class)->getDefinition();

    expect($definition->hasArgument('key_id'))->toBeTrue()
        ->and($definition->hasArgument('public_key'))->toBeFalse();

    // Behavioural: the material actually comes off the stream.
    $secret = consoleKeypair();

    [$status] = keyCustodyRunCli('k1', keyCustodyPublicKey($secret));

    expect($status)->toBe(0)
        ->and(consoleVerify(consoleMint($secret, consoleClaims(), 'k1'))->keyId)->toBe('k1');

    // An empty stream is a refusal, never an empty-string delivery.
    [$emptyStatus, $emptyOutput] = keyCustodyRunCli('k2', null);

    expect($emptyStatus)->toBe(1)
        ->and($emptyOutput)->toContain('stdin')
        ->and(ConsoleKey::query()->count())->toBe(1);
});

it('refuses the artisan verb without --local, exactly as the credential verbs do (AC9)', function (): void {
    keyCustodyClaimedDeployment();

    [$status] = keyCustodyRunCli('k1', keyCustodyPublicKey(), local: false);

    expect($status)->toBe(1)
        ->and(ConsoleKey::query()->count())->toBe(0);
});

// ------------------------------------------------- AC10 — idempotent-safe

it('refuses a repeated key id cleanly and never replaces the material behind it (AC10)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();
    $original = keyCustodyPublicKey();
    $replacement = keyCustodyPublicKey();

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $original], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertCreated();

    // Different material under a live key id: key substitution, refused.
    $substitution = $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $replacement], [
        'Authorization' => $writer->bearerHeader(),
    ]);

    // A CLEAN refusal — the contract's prose shape, not a 500.
    $substitution->assertStatus(409)->assertJsonStructure(['message']);

    // The SAME material under the same key id is the same refusal: a key
    // id names one key for the life of the row, and the surface does not
    // special-case identical bytes.
    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $original], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertStatus(409);

    // One row, original material intact.
    expect(ConsoleKey::query()->count())->toBe(1)
        ->and(ConsoleKey::query()->sole()->public_key)->toBe($original);

    // Same on the claim envelopes, and there the refusal takes the whole
    // claim with it.
    $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('dupe@example.test', keyAuthority: true),
        'console_key' => ['key_id' => 'k1', 'public_key' => $replacement],
    ])->assertStatus(409)->assertJsonStructure(['message']);

    expect(ConsoleKey::query()->count())->toBe(1)
        ->and(ConsoleKey::query()->sole()->public_key)->toBe($original);
});

// ------------------------------------- AC11 — private material, honestly

it('refuses a 64-byte ed25519 SECRET key on both transports, and cannot detect a 32-byte seed (AC11)', function (): void {
    keyCustodyClaimedDeployment();

    $writer = keyCustodyWriter();

    // (1) DETECTABLE. The 64-byte expanded secret key is 128 hex
    // characters; nothing of that length stores, and the column is not
    // even wide enough to hold it.
    $secret = consoleKeypair();
    $secretKeyHex = bin2hex($secret->raw());

    expect(strlen($secretKeyHex))->toBe(128);

    $this->postJson('/bfc/console/re-key', ['key_id' => 'sk', 'public_key' => $secretKeyHex], [
        'Authorization' => $writer->bearerHeader(),
    ])->assertStatus(422);

    [$cliStatus] = keyCustodyRunCli('sk', $secretKeyHex);

    expect($cliStatus)->toBe(1);

    $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('sk@example.test', keyAuthority: true),
        'console_key' => ['key_id' => 'sk', 'public_key' => $secretKeyHex],
    ])->assertStatus(422);

    expect(ConsoleKey::query()->count())->toBe(0);

    // (2) NOT DETECTABLE, and this test says so rather than pretending
    // otherwise. An Ed25519 SEED is 32 bytes — the same size as a public
    // key — and roughly one seed in twenty encodes a usable curve point,
    // at which point NOTHING distinguishes it from a public key by
    // inspection. The value below is a throwaway seed generated for this
    // test precisely because it passes libsodium's point test.
    //
    // It files. That is the documented custody limit (ConsoleKeyring's
    // class docblock): custody is held by the provisioning protocol and
    // by this package having no code that signs, NOT by validation. A
    // seed filed here still buys an attacker nothing from this app — it
    // is a verification key that verifies nothing the vendor signed —
    // but the delivery surface cannot be the thing that catches it, and
    // a test asserting otherwise would be asserting a fiction.
    $seedThatPassesThePointTest = '48c67e0a35aec6a8f83fdaf83d1799f4eec4e50a01fadd581fdfcb7d45e2fb86';

    expect(strlen((string) hex2bin($seedThatPassesThePointTest)))->toBe(32);

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'seed',
        'public_key' => $seedThatPassesThePointTest,
    ], ['Authorization' => $writer->bearerHeader()])->assertCreated();

    expect(ConsoleKey::query()->sole()->public_key)->toBe($seedThatPassesThePointTest);
});

it('never reveals key material back out of any delivery surface (AC11, A7)', function (): void {
    // The claim envelope, on a fresh deployment.
    $claimPublic = keyCustodyPublicKey();

    $claim = $this->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode(),
        'console_key' => ['key_id' => 'k1', 'public_key' => $claimPublic],
    ]);

    $claim->assertCreated();

    expect($claim->getContent())->not->toContain($claimPublic)
        ->and(array_keys((array) $claim->json('console_key')))
        ->toBe(['key_id', 'status', 'activated_at', 'active_key_ids']);

    // The route.
    $routePublic = keyCustodyPublicKey();

    $response = $this->postJson('/bfc/console/re-key', ['key_id' => 'k2', 'public_key' => $routePublic], [
        'Authorization' => keyCustodyWriter()->bearerHeader(),
    ]);

    $response->assertCreated();

    expect($response->getContent())->not->toContain($routePublic);

    // And the CLI's operator transcript.
    $cliPublic = keyCustodyPublicKey();

    [$cliStatus, $cliOutput] = keyCustodyRunCli('k3', $cliPublic);

    expect($cliStatus)->toBe(0)
        ->and($cliOutput)->not->toContain($cliPublic);

    // The shared result object carries no material to leak in the first
    // place: a key id, an instant and a list of key ids, with no
    // ConsoleKey model on it whose `public_key` a dump or a log could
    // reach (rework A7 — an earlier revision held the model and said it
    // did not).
    $properties = array_map(
        static fn (ReflectionProperty $property): string => $property->getName(),
        (new ReflectionClass(ConsoleKeyFiled::class))->getProperties(),
    );

    expect($properties)->toBe(['keyId', 'activatedAt', 'activeKeyIds']);
});

// ------------------- the legacy-admin boundary, decided rather than drifted

it('lets the deployment OWNER re-key with the token its own claim minted (AC14)', function (): void {
    // This is the case that decides whether legacy admin `api_tokens`
    // rows should be excluded from `console:key:write`. They should not:
    // the owner token IS such a row, minted by the current, entirely
    // undeprecated ownership claim, and its holder is the party a
    // console key names. Excluding it would lock the deployment owner
    // out of keying their own deployment.
    $ownerToken = keyCustodyClaimedDeployment();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'owner-filed',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => 'Bearer '.$ownerToken])->assertCreated();

    expect(ConsoleKey::query()->sole()->key_id)->toBe('owner-filed');

    // And the exclusion would be no boundary anyway: an admin
    // `api_tokens` row can mint itself an operator credential carrying
    // the ability, in one request, with no further authority.
    $minted = $this->postJson('/bfc/credentials', [
        'subject_type' => 'operator',
        'subject_ref' => 'self-granted',
        'abilities' => [OperatorAbility::ConsoleKeyWrite->value],
    ], ['Authorization' => 'Bearer '.$ownerToken]);

    $minted->assertCreated();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'self-granted',
        'public_key' => keyCustodyPublicKey(),
    ], ['Authorization' => 'Bearer '.(string) $minted->json('delivery.secret')])->assertCreated();

    expect(ConsoleKey::query()->count())->toBe(2);
});

// ------------------------------- Advisory 1 — the lost-race refusal shape

/**
 * Insert a row carrying `$publicKey` the Nth time a query reads the
 * console keyring BY MATERIAL — which is how a concurrent delivery looks
 * from inside this one.
 *
 * Reading position 1 is {@see FileConsoleKey}'s own pre-check, so racing
 * it lands on {@see ConsoleKeyring::add()}'s re-check (an
 * InvalidArgumentException); position 2 is that re-check, so racing it
 * lands on the unique index itself (a UniqueConstraintViolationException).
 * Both are real driver behaviour, not a stubbed keyring — which matters,
 * because ConsoleKeyring is final and a stub would have been testing a
 * different class.
 */
function keyCustodyRaceAfterMaterialRead(int $afterReads, string $publicKey): void
{
    $reads = 0;
    $raced = false;

    DB::listen(function (QueryExecuted $query) use (&$reads, &$raced, $afterReads, $publicKey): void {
        if ($raced
            || ! str_contains($query->sql, 'bfc_console_keys')
            || ! str_contains($query->sql, 'public_key')
            || ! str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
            return;
        }

        if (++$reads < $afterReads) {
            return;
        }

        $raced = true;

        DB::table('bfc_console_keys')->insert([
            'id' => (string) Str::uuid(),
            'key_id' => 'winner-'.bin2hex(random_bytes(4)),
            'public_key' => $publicKey,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    });
}

/**
 * Run one delivery through the action and hand back whatever escaped.
 */
function keyCustodyAttemptDelivery(string $keyId, string $publicKey): ?Throwable
{
    try {
        DB::transaction(function () use ($keyId, $publicKey): void {
            app(FileConsoleKey::class)(ConsoleKeyDelivery::fromParts($keyId, $publicKey), null);
        });
    } catch (Throwable $escaped) {
        return $escaped;
    }

    return null;
}

it('answers a lost uniqueness race with one clean 409 and never a 500 (Advisory 1)', function (int $afterReads, string $expectedCause): void {
    keyCustodyClaimedDeployment();

    $public = keyCustodyPublicKey();

    keyCustodyRaceAfterMaterialRead($afterReads, $public);

    $escaped = keyCustodyAttemptDelivery('raced', $public);

    expect($escaped)->toBeInstanceOf(ConsoleKeyRefused::class);

    /** @var ConsoleKeyRefused $escaped */
    expect($escaped->reason)->toBe(ConsoleKeyRefusal::ConcurrentDelivery)
        ->and($escaped->reason->status())->toBe(409)
        ->and($escaped->getMessage())->not->toBe('')
        // The cause proves the two datasets drove two DIFFERENT branches
        // rather than both landing on the same one — the ring's own
        // re-check, and the unique index underneath it.
        ->and($escaped->getPrevious())->toBeInstanceOf($expectedCause);

    // The losing delivery wrote nothing of its own. (What the RACER
    // wrote is rolled back with it here: sqlite gives the suite one
    // connection, so the injected row shares this transaction. That is a
    // property of the harness, not of the code — the assertion that
    // matters is that this delivery's key id was never filed.)
    expect(ConsoleKey::query()->where('key_id', 'raced')->exists())->toBeFalse();
})->with([
    // Racing the action's own pre-check lands on the ring's re-check…
    'losing to the ring re-check' => [1, InvalidArgumentException::class],
    // …and racing that lands on the unique index itself.
    'losing to the unique index' => [2, UniqueConstraintViolationException::class],
]);

it('lets a real database fault travel as a fault, not as a refusal (Advisory 1)', function (): void {
    keyCustodyClaimedDeployment();

    // The catch is narrow on purpose. A connection drop, a permission
    // failure or a full disk is NOT "that key id is taken", and
    // reporting one that way would send an operator hunting a key that
    // is not there. This provokes a genuine, NON-unique QueryException
    // by taking the table out from under the insert.
    $broken = false;

    DB::listen(function (QueryExecuted $query) use (&$broken): void {
        if ($broken
            || ! str_contains($query->sql, 'bfc_console_keys')
            || ! str_contains($query->sql, 'public_key')
            || ! str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
            return;
        }

        $broken = true;

        Schema::drop('bfc_console_keys');
    });

    $escaped = keyCustodyAttemptDelivery('fault', keyCustodyPublicKey());

    expect($escaped)->toBeInstanceOf(QueryException::class)
        ->and($escaped)->not->toBeInstanceOf(ConsoleKeyRefused::class)
        ->and($escaped)->not->toBeInstanceOf(UniqueConstraintViolationException::class);
});
