<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * The key-retirement operator path (Console PRD D12, PR9): the half of
 * make-before-break that had no operator surface at all.
 *
 * `ConsoleKeyring::retire()` was reachable only from PHP running inside
 * the app, so a deployment that had re-keyed over HTTP or the CLI could
 * start trusting the incoming key and never stop trusting the outgoing
 * one. Every rotation stayed half-finished.
 *
 * What these tests defend, in the order the file walks them:
 *
 *  1. **An operator can retire a filed key on either transport**, and
 *     the two have identical effects.
 *  2. **The gate is `console:key:write`**, and every other credential
 *     fails — the same gate the filing half rides, because whoever can
 *     file a key can already enter as a delegated admin.
 *  3. **Retiring the LAST ACTIVE key ends delegated entry**, is
 *     permitted, and is refused without an affirmative confirmation.
 *  4. **One retirement, one audit event**, on the same stream the filing
 *     half writes to, in the state change's own transaction.
 *  5. **Idempotent, and honest about it**: a repeat succeeds, carries
 *     the ORIGINAL instant, and writes no second event.
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
 * Local rather than borrowed from another test file so this suite runs
 * standalone under a `--filter`, which is the convention `tests/Pest.php`
 * states for shared helpers.
 *
 * @param  list<string>|null  $abilities
 */
function retirementOperator(?array $abilities): MintedTestCredential
{
    return test()->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'retire-'.bin2hex(random_bytes(4)),
        'abilities' => $abilities,
    ]);
}

function retirementWriter(): MintedTestCredential
{
    return retirementOperator([OperatorAbility::ConsoleKeyWrite->value]);
}

/**
 * Claim the deployment, the way a fleet that predates this feature is
 * already claimed. Filing refuses on an unclaimed instance.
 */
function retirementClaimedDeployment(): void
{
    OwnershipClaim::query()->create(['token_hash' => OwnershipClaim::hashToken('retire-owner')]);

    test()->postJson('/bfc/ownership/claim', ['token' => 'retire-owner'])->assertCreated();
}

/**
 * File and activate one key through the real re-key verb, and hand back
 * the secret half so a test can mint an assertion under it.
 */
function retirementFiledKey(string $keyId, MintedTestCredential $writer): AsymmetricSecretKey
{
    $secret = consoleKeypair();

    test()->postJson('/bfc/console/re-key', [
        'key_id' => $keyId,
        'public_key' => $secret->getPublicKey()->toHexString(),
    ], ['Authorization' => $writer->bearerHeader()])->assertCreated();

    return $secret;
}

function retirementUrl(string $keyId): string
{
    return '/bfc/console/keys/'.$keyId.'/retire';
}

/**
 * Every key id verifying right now, sorted.
 *
 * @return list<string>
 */
function retirementActiveIds(): array
{
    return array_map(
        static fn (ConsoleKey $key): string => $key->key_id,
        (new ConsoleKeyring)->active(),
    );
}

/**
 * Run the CLI verb.
 *
 * Driven through `Command::run()` rather than Laravel's `artisan()`
 * helper so the exit status is read directly rather than through an
 * expectation DSL — the status IS the assertion here.
 *
 * @return array{int, string} exit status and captured output
 */
function retirementRunCli(string $keyId, bool $confirm = false, bool $local = true): array
{
    $command = app(ConsoleRetireKeyCommand::class);
    $command->setLaravel(app());

    $parameters = ['key_id' => $keyId];

    if ($local) {
        $parameters['--local'] = true;
    }

    if ($confirm) {
        $parameters['--confirm-last-active-key'] = true;
    }

    $output = new BufferedOutput;
    $status = $command->run(new ArrayInput($parameters), $output);

    return [$status, $output->fetch()];
}

// ------------------------------- AC1 — an operator can retire a key ---

it('retires a filed key over HTTP and stops it verifying', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    $outgoing = retirementFiledKey('k1', $writer);
    $incoming = retirementFiledKey('k2', $writer);

    // The overlap first: both keys verify, which is the state a re-key
    // leaves behind and the state this verb exists to end.
    expect(retirementActiveIds())->toBe(['k1', 'k2']);

    // A pending key too, so "other keys are unchanged" is checked
    // against a row in every lifecycle state rather than only the one
    // that happens to be verifying.
    $pending = ConsoleKey::query()->create([
        'key_id' => 'k3-pending',
        'public_key' => ConsoleKeyring::normalizePublicKey(consoleKeypair()->getPublicKey()->toHexString()),
    ]);

    $untouched = ConsoleKey::query()
        ->whereIn('key_id', ['k2', 'k3-pending'])
        ->orderBy('key_id')
        ->get()
        ->map(static fn (ConsoleKey $key): array => $key->only(['key_id', 'public_key', 'activated_at', 'retired_at']))
        ->all();

    $response = $this->postJson(retirementUrl('k1'), [], [
        'Authorization' => $writer->bearerHeader(),
    ]);

    $response->assertOk()
        ->assertJsonPath('console_key_retired.key_id', 'k1')
        ->assertJsonPath('console_key_retired.status', 'retired')
        ->assertJsonPath('console_key_retired.newly_retired', true)
        ->assertJsonPath('console_key_retired.active_key_ids', ['k2']);

    // The EFFECT, read from the verifier rather than from the row: the
    // retired key refuses, the surviving one still verifies.
    expect(retirementActiveIds())->toBe(['k2'])
        ->and(consoleRefusal(consoleMint($outgoing, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey)
        ->and(consoleVerify(consoleMint($incoming, consoleClaims(), 'k2'))->keyId)->toBe('k2');

    // "Other keys are UNCHANGED" — the wording the CLI description and
    // the contract now use, and it is checked field by field rather than
    // inferred from what still verifies. The earlier wording was "other
    // filed keys keep verifying", which is false of the pending row
    // below and of any already-retired one.
    expect(ConsoleKey::query()
        ->whereIn('key_id', ['k2', 'k3-pending'])
        ->orderBy('key_id')
        ->get()
        ->map(static fn (ConsoleKey $key): array => $key->only(['key_id', 'public_key', 'activated_at', 'retired_at']))
        ->all())->toEqual($untouched);

    // And the retired ROW is retained rather than removed, which is what
    // keeps its material permanently unre-filable.
    expect(ConsoleKey::query()->count())->toBe(3)
        ->and(ConsoleKey::query()->where('key_id', 'k1')->sole()->public_key)
        ->toBe(ConsoleKeyring::normalizePublicKey($outgoing->getPublicKey()->toHexString()))
        ->and($pending->refresh()->retired_at)->toBeNull();
});

it('retires a filed key on the cli transport with identical effect', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    $outgoing = retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    [$status, $output] = retirementRunCli('k1');

    expect($status)->toBe(0)
        ->and($output)->toContain('stopped verifying')
        ->and($output)->toContain('Keys still verifying: k2')
        // The transcript says what authorized this, because nothing else
        // does: this transport has no credential gate.
        ->and($output)->toContain(AuditActorType::CliOperator->value)
        ->and($output)->toContain(OperatorAbility::ConsoleKeyWrite->value);

    expect(retirementActiveIds())->toBe(['k2'])
        ->and(consoleRefusal(consoleMint($outgoing, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey);
});

it('refuses the cli verb without --local, and retires nothing', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    [$status, $output] = retirementRunCli('k1', local: false);

    expect($status)->toBe(1)
        ->and($output)->toContain('--local')
        ->and(retirementActiveIds())->toBe(['k1', 'k2']);
});

it('answers 404 for a key id that is not on the ring, malformed ones included', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    // Never filed.
    $this->postJson(retirementUrl('k9'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertStatus(404)
        ->assertJsonStructure(['message']);

    // Malformed: outside the `kid` charset, so it cannot name a row.
    // Two forms, one of which would be a second path segment if the
    // route matched it at all.
    foreach (['k1%20k2', 'k'.str_repeat('9', 64)] as $malformed) {
        $this->postJson(retirementUrl($malformed), [], ['Authorization' => $writer->bearerHeader()])
            ->assertStatus(404);
    }

    // The CLI answers the same, with a non-zero status.
    [$status] = retirementRunCli('k9');

    expect($status)->toBe(1)
        // Nothing was touched by any of it.
        ->and(retirementActiveIds())->toBe(['k1', 'k2'])
        ->and(ConsoleKey::query()->whereNotNull('retired_at')->count())->toBe(0);
});

// --------------------------------------------------- AC2 — the gate ---

it('gates retirement on console:key:write and refuses every other credential', function (): void {
    retirementClaimedDeployment();

    $filer = retirementWriter();

    foreach (['k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'k8', 'k9'] as $keyId) {
        retirementFiledKey($keyId, $filer);
    }

    // Not one of these may end a signing authority.
    foreach ([
        OperatorAbility::CredentialRead,
        OperatorAbility::CredentialMint,
        OperatorAbility::CredentialRotate,
        OperatorAbility::CredentialRevoke,
        OperatorAbility::SubjectOffboard,
        OperatorAbility::AuditRead,
        OperatorAbility::McpRead,
        OperatorAbility::McpAdmin,
        OperatorAbility::MetadataRead,
    ] as $ability) {
        $narrow = retirementOperator([$ability->value]);

        $this->postJson(retirementUrl('k1'), [], ['Authorization' => $narrow->bearerHeader()])
            ->assertStatus(UniformConsoleKeyRefusal::STATUS);
    }

    // Neither may a credential with no abilities at all, nor no
    // credential at all.
    $this->postJson(retirementUrl('k1'), [], ['Authorization' => retirementOperator([])->bearerHeader()])
        ->assertStatus(UniformConsoleKeyRefusal::STATUS);

    $this->postJson(retirementUrl('k1'))->assertStatus(UniformConsoleKeyRefusal::STATUS);

    // Nothing above retired anything.
    expect(ConsoleKey::query()->whereNotNull('retired_at')->count())->toBe(0);

    // The dedicated ability works…
    $this->postJson(retirementUrl('k1'), [], ['Authorization' => retirementWriter()->bearerHeader()])
        ->assertOk();

    // …so does the explicit break-glass, a marking an operator chose…
    $this->postJson(retirementUrl('k2'), [], [
        'Authorization' => retirementOperator([OperatorAbility::ADMIN])->bearerHeader(),
    ])->assertOk();

    // …and so does a legacy admin token, as on every operator surface.
    $adminPlaintext = 'legacy-admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'legacy-admin',
        'token_hash' => hash('sha256', $adminPlaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    $this->postJson(retirementUrl('k3'), [], ['Authorization' => 'Bearer '.$adminPlaintext])
        ->assertOk();

    expect(ConsoleKey::query()->whereNotNull('retired_at')->pluck('key_id')->sort()->values()->all())
        ->toBe(['k1', 'k2', 'k3']);
});

it('answers one identical refusal to every pre-authorization failure', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    $expired = retirementOperator([OperatorAbility::ConsoleKeyWrite->value]);
    $expired->credential->forceFill(['expires_at' => now()->subDay()])->save();

    $bodies = [];

    foreach ([
        null,
        'Bearer not-a-credential',
        $expired->bearerHeader(),
        retirementOperator([OperatorAbility::CredentialRotate->value])->bearerHeader(),
    ] as $header) {
        $response = $this->postJson(retirementUrl('k1'), [], $header === null ? [] : ['Authorization' => $header]);

        $response->assertStatus(UniformConsoleKeyRefusal::STATUS);

        $bodies[] = $response->json();
    }

    // Byte for byte the same answer: a prober learns only that it was
    // refused, never whether it holds the credential that can take the
    // deployment.
    expect(array_unique(array_map(json_encode(...), $bodies)))->toHaveCount(1)
        ->and($bodies[0])->toBe(['message' => UniformConsoleKeyRefusal::MESSAGE])
        ->and(retirementActiveIds())->toBe(['k1', 'k2']);
});

// ------------------------------------- AC3 — the last active key ------

it('refuses to retire the last key that still verifies until the request confirms it', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    $only = retirementFiledKey('k1', $writer);

    $refused = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()]);

    $refused->assertStatus(409)->assertJsonStructure(['message']);

    // NOTHING was retired, and the key still verifies — the whole point
    // of a refusal that is not a warning.
    expect(retirementActiveIds())->toBe(['k1'])
        ->and(consoleVerify(consoleMint($only, consoleClaims(), 'k1'))->keyId)->toBe('k1')
        ->and(ConsoleKey::query()->whereNotNull('retired_at')->count())->toBe(0);

    // A truthy-looking value is NOT the confirmation: absence is the
    // safe reading, and only the literal boolean is affirmative.
    foreach (['true', 1, 'yes', ['confirm']] as $notTrue) {
        $this->postJson(retirementUrl('k1'), ['confirm_last_active_key' => $notTrue], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertStatus(409);
    }

    expect(retirementActiveIds())->toBe(['k1']);

    // The CLI refuses on the same terms, and names the flag that would
    // proceed.
    [$status, $output] = retirementRunCli('k1');

    expect($status)->toBe(1)
        ->and($output)->toContain('--confirm-last-active-key')
        ->and(retirementActiveIds())->toBe(['k1']);
});

it('retires the last active key on an explicit confirmation and says nothing verifies', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    $only = retirementFiledKey('k1', $writer);

    $this->postJson(retirementUrl('k1'), ['confirm_last_active_key' => true], [
        'Authorization' => $writer->bearerHeader(),
    ])
        ->assertOk()
        ->assertJsonPath('console_key_retired.newly_retired', true)
        // The empty list IS the report that delegated entry has ended.
        ->assertJsonPath('console_key_retired.active_key_ids', []);

    // The consequence, read from the verifier: nothing verifies, so
    // nobody can be handed to this deployment.
    expect(retirementActiveIds())->toBe([])
        ->and(consoleRefusal(consoleMint($only, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey);

    // And it cannot be undone by re-filing the same bytes: recovery
    // needs a freshly generated keypair.
    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1-again',
        'public_key' => $only->getPublicKey()->toHexString(),
    ], ['Authorization' => $writer->bearerHeader()])->assertStatus(409);

    expect(retirementActiveIds())->toBe([]);
});

it('confirms the last active key on the cli transport too', function (): void {
    retirementClaimedDeployment();

    retirementFiledKey('k1', retirementWriter());

    [$status, $output] = retirementRunCli('k1', confirm: true);

    expect($status)->toBe(0)
        ->and($output)->toContain('No console key verifies any more')
        ->and(retirementActiveIds())->toBe([]);
});

it('asks for no confirmation to retire a pending key or one of two active keys', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    // One of two active keys: the deployment can still be entered
    // afterwards, so the rule does not bite.
    $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('console_key_retired.active_key_ids', ['k2']);

    // A PENDING key while k2 is the only ACTIVE one. Retiring it does
    // not change what verifies, so it is not the last-active-key case
    // however few keys are on the ring.
    $pending = consoleKeypair();

    ConsoleKey::query()->create([
        'key_id' => 'k3-pending',
        'public_key' => ConsoleKeyring::normalizePublicKey($pending->getPublicKey()->toHexString()),
    ]);

    $this->postJson(retirementUrl('k3-pending'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('console_key_retired.newly_retired', true)
        ->assertJsonPath('console_key_retired.active_key_ids', ['k2']);

    expect(retirementActiveIds())->toBe(['k2']);
});

it('refuses the second of two sequential retirements once it is the last active key', function (): void {
    // SEQUENTIAL, and the title says so. The inputs are request one,
    // commit, request two — there are no overlapping transactions here,
    // so nothing about CONCURRENT retirement is established by this test
    // passing. What it does establish: the last-active-key rule is read
    // from the ring at each call rather than from anything cached, so a
    // retirement that was fine a moment ago is refused once the ring has
    // moved under it.
    //
    // The concurrent case needs a driver that honours row locks and is
    // tracked as mutation debt (`console-key-retire-ring-lock`), not
    // claimed by this title.
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();

    $this->postJson(retirementUrl('k2'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertStatus(409);

    expect(retirementActiveIds())->toBe(['k2']);
});

// --------------------------------------------------- AC4 — the audit --

it('audits one retirement to the lifecycle stream with the actor typed and no key material', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    $secret = retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    $public = $secret->getPublicKey()->toHexString();

    $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();

    $retired = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('note', 'like', 'console countersigning key retired%')
        ->sole();

    expect($retired->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($retired->actor_ref)->toBe($writer->credential->id)
        // A console key is no row in the credential stores, so the
        // identity lives in the bounded note.
        ->and($retired->credential_id)->toBeNull()
        ->and((string) $retired->note)->toContain('k1')
        ->and((string) $retired->note)->toContain('keys still verifying: k2')
        ->and((string) $retired->note)->not->toContain($public);

    // The filing half wrote to the SAME stream, so one rotation reads as
    // one contiguous story rather than two.
    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::Delivered->value)->count())->toBe(2)
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::Activated->value)->count())->toBe(2);
});

it('audits a cli retirement as cli_operator, and names an empty ring in the note', function (): void {
    retirementClaimedDeployment();

    retirementFiledKey('k1', retirementWriter());

    [$status] = retirementRunCli('k1', confirm: true);

    expect($status)->toBe(0);

    $retired = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('note', 'like', 'console countersigning key retired%')
        ->sole();

    expect($retired->actor_type)->toBe(AuditActorType::CliOperator)
        ->and($retired->actor_ref)->toBeNull()
        ->and((string) $retired->note)->toContain('keys still verifying: none');
});

it('audits a refused retirement without writing a malformed key id', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);

    // The last-active refusal.
    $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertStatus(409);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console countersigning key retirement refused%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied->actor_ref)->toBe($writer->credential->id)
        ->and((string) $denied->note)->toContain(ConsoleKeyRefusal::LastActiveKey->value)
        ->and((string) $denied->note)->toContain('key id k1');

    // A hostile key id is DROPPED rather than truncated into the note:
    // unvalidated caller text does not belong in a row that renders in
    // an operator's console.
    app(RetireConsoleKey::class)->recordRefusal(
        ConsoleKeyRefused::because(ConsoleKeyRefusal::UnknownKeyId),
        AuditActor::cliOperator(),
        "k1\nfabricated: audit line",
    );

    $hostile = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', '%'.ConsoleKeyRefusal::UnknownKeyId->value.'%')
        ->sole();

    expect((string) $hostile->note)->not->toContain('fabricated')
        ->and((string) $hostile->note)->not->toContain('key id');
});

it('records nothing when the retirement transaction rolls back', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    $before = CredentialAuditEvent::query()->count();

    // The audit row lives or dies with the state change, because it IS
    // the record of it.
    try {
        DB::transaction(function (): void {
            app(RetireConsoleKey::class)('k1', AuditActor::cliOperator());

            throw new RuntimeException('the caller failed after the retirement');
        });
    } catch (RuntimeException) {
        // Expected.
    }

    expect(retirementActiveIds())->toBe(['k1', 'k2'])
        ->and(ConsoleKey::query()->whereNotNull('retired_at')->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe($before);
});

// The outside-a-transaction case is NOT here. RefreshDatabase wraps
// every test in this file in a transaction, so `transactionLevel()` is
// never 0 and the case is unreachable — which is how the first version
// of that check came to be a reflection scan over the action's source,
// green for a weaker reason than its title claimed. It is driven for
// real, against the ring, in `tests/ConsoleKeyRetirementTransactionTest.php`.

// ------------------------------------------ AC5 — idempotency ---------

it('is idempotent, answering a repeat with the original instant and no new event', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    // FROZEN. The whole assertion is that the second answer carries the
    // FIRST call's instant, and a wall-clock read between the two calls
    // would make the comparison a race rather than a check.
    $this->freezeTime();

    $first = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();

    $retiredAt = $first->json('console_key_retired.retired_at');

    expect($retiredAt)->toBeString()
        ->and($first->json('console_key_retired.newly_retired'))->toBeTrue();

    // Time moves on. A verb that answered with "now" would answer
    // differently here; an idempotent one does not.
    $this->travel(90)->seconds();

    $repeat = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()]);

    $repeat->assertOk()
        ->assertJsonPath('console_key_retired.key_id', 'k1')
        ->assertJsonPath('console_key_retired.status', 'retired')
        // The one field that differs, and the whole of how the verb
        // stays honest while staying idempotent.
        ->assertJsonPath('console_key_retired.newly_retired', false)
        ->assertJsonPath('console_key_retired.retired_at', $retiredAt)
        ->assertJsonPath('console_key_retired.active_key_ids', ['k2']);
});

it('reports the ring as of each response while the key id status and retired_at stay fixed', function (): void {
    // THE NARROWED CLAIM, driven by running the case it describes. An
    // earlier revision of the contract said a repeat answers "the same
    // object", which is false the moment the ring moves under it — and
    // the first version of the idempotency test could not see that,
    // because nothing changed between its two calls.
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    $this->freezeTime();

    $first = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('console_key_retired.active_key_ids', ['k2']);

    $retiredAt = $first->json('console_key_retired.retired_at');

    // The ring MOVES between the two calls.
    $this->travel(120)->seconds();
    retirementFiledKey('k3', $writer);

    $repeat = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();

    // Fixed by the retirement: three fields that do not move again.
    $repeat->assertJsonPath('console_key_retired.key_id', 'k1')
        ->assertJsonPath('console_key_retired.status', 'retired')
        ->assertJsonPath('console_key_retired.retired_at', $retiredAt)
        ->assertJsonPath('console_key_retired.newly_retired', false);

    // NOT fixed, and deliberately: it answers "what verifies now".
    $repeat->assertJsonPath('console_key_retired.active_key_ids', ['k2', 'k3']);

    expect($repeat->json('console_key_retired.active_key_ids'))
        ->not->toBe($first->json('console_key_retired.active_key_ids'));
});

it('ignores unknown body fields and reads only the literal confirmation', function (): void {
    // The contract says `confirm_last_active_key` is the only field this
    // route INTERPRETS, not that a body carrying anything else is
    // refused. Run the case the sentence describes, in both directions.
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);

    // Unknown siblings ride along and change nothing: the confirmation
    // is absent, so the last-active-key rule still refuses.
    $this->postJson(retirementUrl('k1'), [
        'confirm_last_active_key' => false,
        'unexpected' => 'anything',
        'key_id' => 'k9',
    ], ['Authorization' => $writer->bearerHeader()])->assertStatus(409);

    expect(retirementActiveIds())->toBe(['k1']);

    // And with the literal confirmation present, the same unknown
    // siblings do not stop it either.
    $this->postJson(retirementUrl('k1'), [
        'confirm_last_active_key' => true,
        'unexpected' => 'anything',
    ], ['Authorization' => $writer->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('console_key_retired.newly_retired', true);

    expect(retirementActiveIds())->toBe([]);
});

it('writes no second audit event when an already-retired key is retired again', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    foreach (range(1, 3) as $ignored) {
        $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();
    }

    // One retirement, one event. An event per CALL would record
    // retirements that never happened.
    expect(CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('note', 'like', 'console countersigning key retired%')
        ->count())->toBe(1);

    // Nor is a repeat a refusal: nothing was denied, so nothing audits
    // as denied either.
    expect(CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console countersigning key retirement refused%')
        ->count())->toBe(0);
});

it('exits zero for a retirement and for a repeat, and one for a refusal, on the cli transport', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    [$retired, $firstOutput] = retirementRunCli('k1');
    [$repeat, $repeatOutput] = retirementRunCli('k1');
    [$unknown] = retirementRunCli('k9');
    // k2 is now the last active key: refused without confirmation.
    [$lastActive] = retirementRunCli('k2');

    expect([$retired, $repeat, $unknown, $lastActive])->toBe([0, 0, 1, 1])
        ->and($firstOutput)->toContain('stopped verifying')
        // The status does not distinguish them; the transcript does.
        ->and($repeatOutput)->toContain('ALREADY retired')
        ->and(retirementActiveIds())->toBe(['k2']);
});

// ------------------------------ AC8-adjacent — the throttle rides too --

it('rate-limits retirement as an operator write', function (): void {
    retirementClaimedDeployment();

    $writer = retirementWriter();

    // Two filings, which are operator writes on the same limiter and
    // therefore already spend two of the minute's budget from this
    // address.
    retirementFiledKey('k1', $writer);
    retirementFiledKey('k2', $writer);

    // The first retires; every repeat is an idempotent 200 — and each
    // one still spends limiter budget, because the throttle runs BEFORE
    // the gate and the controller. 58 of them brings the address to the
    // 60/min bound exactly.
    for ($i = 1; $i <= 58; $i++) {
        $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()])->assertOk();
    }

    $throttled = $this->postJson(retirementUrl('k1'), [], ['Authorization' => $writer->bearerHeader()]);

    // 429 stays 429: the uniform-refusal middleware sits INSIDE the
    // throttle, so a rate limit never disguises itself as a refusal.
    $throttled->assertStatus(429);

    // Bounded across addresses too: the per-credential bucket is the one
    // that makes a stolen credential bounded wherever it is replayed.
    $this->withServerVariables(['REMOTE_ADDR' => '10.9.9.9'])
        ->postJson(retirementUrl('k2'), [], ['Authorization' => $writer->bearerHeader()])
        ->assertStatus(429);

    // k2 was never retired: the throttle refused before the controller.
    expect(retirementActiveIds())->toBe(['k2']);
});
