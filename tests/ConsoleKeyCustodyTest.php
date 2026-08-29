<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
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
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Queue;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * Console countersigning-key custody (Console PRD D12, PR2): how this
 * deployment comes to hold the vendor's per-deployment PUBLIC key — at
 * claim time, and afterwards through the re-key verb that retrofits a
 * fleet which has already claimed.
 *
 * The two properties every test here is really defending:
 *
 *  1. **Additive.** An envelope that carries no key behaves exactly as
 *     it did before this release, down to its response keys.
 *  2. **Make-before-break.** A re-key activates a new key and retires
 *     nothing, so a LIVE deployment can be re-keyed mid-traffic;
 *     retirement is a separate, later act.
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
 * An operator credential that may re-key.
 */
function keyCustodyRotator(): MintedTestCredential
{
    return keyCustodyOperator([OperatorAbility::CredentialRotate->value]);
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
 * A fresh onboarding claim code, issued through the real verb.
 *
 * Local rather than borrowed from another test file so this suite runs
 * standalone under a `--filter`, which is the convention `tests/Pest.php`
 * states for shared helpers.
 */
function keyCustodyOnboardingCode(string $email = 'console@example.test'): string
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
    ], ['Authorization' => 'Bearer '.$plaintext]);

    $response->assertCreated();

    return (string) $response->json('claim_code');
}

/**
 * The public half of a fresh vendor keypair, in the hex form a real
 * delivery carries.
 */
function keyCustodyPublicKey(AsymmetricSecretKey $secret): string
{
    return $secret->getPublicKey()->toHexString();
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

it('files the delivered public key on the onboarding exchange and reports the key id (AC1)', function (): void {
    $secret = consoleKeypair();
    $public = keyCustodyPublicKey($secret);

    $response = $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('console@example.test'),
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

it('leaves both claim envelopes byte-identical when no key is delivered (AC2)', function (): void {
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

// ------------------------------------------------ AC3 — refused material

it('refuses key material the keyring will not store and files nothing (AC3)', function (): void {
    $rotator = keyCustodyRotator();
    $shape = 0;

    foreach (keyCustodyRejectedMaterial() as $description => $material) {
        $shape++;

        // Through the re-key verb…
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k'.$shape, 'public_key' => $material], [
            'Authorization' => $rotator->bearerHeader(),
        ])->assertStatus(422);

        // …and through the claim envelope, which is the half that proves
        // the claim surface routes into PR1's keyring rather than
        // carrying its own, laxer, check. A fresh address per shape: the
        // claim surface is throttled at 10/min per IP and this loop is
        // about material, not limits.
        $code = keyCustodyClaimCode('claim-'.md5($description));

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.1.'.$shape])
            ->postJson('/bfc/ownership/claim', [
                'token' => $code,
                'console_key' => ['key_id' => 'k'.$shape, 'public_key' => $material],
            ])->assertStatus(422);

        expect(ConsoleKey::query()->count())->toBe(0)
            ->and(Ownership::current()?->owner_token_id)->toBeNull();

        // Fail-closed AND atomic: the single-use code was not spent, so
        // the deployment can still be claimed once the delivery is fixed.
        $this->withServerVariables(['REMOTE_ADDR' => '10.0.1.'.$shape])
            ->postJson('/bfc/ownership/claim', ['token' => $code])->assertCreated();

        // Reset for the next shape.
        Ownership::query()->delete();
    }
});

it('refuses a malformed key id on the same terms as malformed material (AC3)', function (): void {
    $public = keyCustodyPublicKey(consoleKeypair());
    $rotator = keyCustodyRotator();

    // NOT in this list: a trailing newline. Laravel's global TrimStrings
    // middleware strips it before any package code runs, so over HTTP
    // "k1\n" simply IS "k1" and files legitimately. The ring's own `\z`
    // anchor is what refuses it where trimming does not happen — the CLI
    // case below drives exactly that.
    foreach (['', 'has spaces', str_repeat('k', 65), 'k/1', 'k 1'] as $index => $keyId) {
        $this->postJson('/bfc/console/re-key', ['key_id' => $keyId, 'public_key' => $public], [
            'Authorization' => $rotator->bearerHeader(),
        ])->assertStatus(422);

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.2.'.$index])
            ->postJson('/bfc/ownership/claim', [
                'token' => keyCustodyClaimCode('claim-'.md5($keyId)),
                'console_key' => ['key_id' => $keyId, 'public_key' => $public],
            ])->assertStatus(422);
    }

    // The untrimmed transport: argv reaches the ring exactly as typed.
    $this->artisan('bfc:console:re-key', [
        'key_id' => "k1\n",
        'public_key' => $public,
        '--local' => true,
    ])->assertFailed();

    expect(ConsoleKey::query()->count())->toBe(0);
});

it('refuses a half-filled console_key object rather than reading it as absence (AC3)', function (): void {
    $public = keyCustodyPublicKey(consoleKeypair());

    foreach ([['key_id' => 'k1'], ['public_key' => $public], ['key_id' => 'k1', 'public_key' => 42], 'k1'] as $payload) {
        $this->postJson('/bfc/ownership/claim', [
            'token' => keyCustodyClaimCode('claim-'.md5(serialize($payload))),
            'console_key' => $payload,
        ])->assertStatus(422);
    }

    expect(ConsoleKey::query()->count())->toBe(0)
        ->and(Ownership::current()?->owner_token_id)->toBeNull();
});

it('leaves an at-exchange claim code presentable when the delivered key is refused (AC3)', function (): void {
    keyCustodyBurnAtExchange();

    $code = keyCustodyOnboardingCode('rollback@example.test');

    $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k1', 'public_key' => bin2hex(random_bytes(31))],
    ])->assertStatus(422);

    $row = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole();

    expect($row->consumed_at)->toBeNull()
        ->and($row->durable_token_id)->toBeNull()
        ->and(ConsoleKey::query()->count())->toBe(0);

    // …and the fixed delivery still works on the same code.
    $this->postJson('/bfc/onboarding/exchange', [
        'token' => $code,
        'console_key' => ['key_id' => 'k1', 'public_key' => keyCustodyPublicKey(consoleKeypair())],
    ])->assertCreated();
});

// ----------------------------------------- AC4 — re-key, make-before-break

it('re-keys an already-claimed deployment without re-onboarding and without retiring (AC4)', function (): void {
    // A deployment that claimed BEFORE this feature existed: no key.
    $claim = $this->postJson('/bfc/ownership/claim', ['token' => keyCustodyClaimCode()]);
    $claim->assertCreated();

    $ownershipBefore = Ownership::current();
    $rotator = keyCustodyRotator();

    // The retrofit: the first key arrives on a live, claimed deployment.
    $first = consoleKeypair();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey($first),
    ], ['Authorization' => $rotator->bearerHeader()])
        ->assertCreated()
        ->assertJsonPath('console_key.key_id', 'k1')
        ->assertJsonPath('console_key.active_key_ids', ['k1']);

    // The rotation: a SECOND key, delivered while the first is live.
    $second = consoleKeypair();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k2',
        'public_key' => keyCustodyPublicKey($second),
    ], ['Authorization' => $rotator->bearerHeader()])
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

    // No re-onboarding happened: the same ownership row, the same owner
    // token, still working.
    expect(Ownership::current()?->owner_token_id)->toBe($ownershipBefore?->owner_token_id)
        ->and(OwnershipClaim::query()->whereNull('consumed_at')->count())->toBe(0);
});

// ----------------------------------------- AC5 — retirement is separate

it('keeps retirement a separate operation that ends only the retired key (AC5)', function (): void {
    $rotator = keyCustodyRotator();
    $first = consoleKeypair();
    $second = consoleKeypair();

    foreach ([['k1', $first], ['k2', $second]] as [$keyId, $secret]) {
        $this->postJson('/bfc/console/re-key', [
            'key_id' => $keyId,
            'public_key' => keyCustodyPublicKey($secret),
        ], ['Authorization' => $rotator->bearerHeader()])->assertCreated();
    }

    // Retirement is a keyring operation, deliberately NOT reachable from
    // the re-key verb: no HTTP path in this release retires a key.
    (new ConsoleKeyring)->retire('k1');

    expect(keyCustodyActiveIds())->toBe(['k2'])
        ->and(consoleRefusal(consoleMint($first, consoleClaims(), 'k1'))->reason)
        ->toBe(AssertionRefusalReason::RetiredKey)
        ->and(consoleVerify(consoleMint($second, consoleClaims(), 'k2'))->keyId)->toBe('k2');
});

// ---------------------------------------------------- AC6 — the gate

it('gates the re-key verb on an operator credential carrying the rotate family (AC6)', function (): void {
    $public = keyCustodyPublicKey(consoleKeypair());
    $body = ['key_id' => 'k1', 'public_key' => $public];

    // No credential at all.
    $anonymous = $this->postJson('/bfc/console/re-key', $body);
    $anonymous->assertUnauthorized();

    // A credential that authenticates but lacks the ability.
    $reader = keyCustodyOperator([OperatorAbility::CredentialRead->value]);
    $this->postJson('/bfc/console/re-key', $body, ['Authorization' => $reader->bearerHeader()])
        ->assertForbidden();

    // A credential with NO abilities at all (least privilege default).
    $bare = keyCustodyOperator(null);
    $this->postJson('/bfc/console/re-key', $body, ['Authorization' => $bare->bearerHeader()])
        ->assertForbidden();

    // Expired and revoked rotate-capable credentials.
    $expired = keyCustodyOperator([OperatorAbility::CredentialRotate->value], ['expires_at' => now()->subMinute()]);
    $revoked = keyCustodyOperator([OperatorAbility::CredentialRotate->value], ['revoked_at' => now()]);

    $expiredResponse = $this->postJson('/bfc/console/re-key', $body, ['Authorization' => $expired->bearerHeader()]);
    $revokedResponse = $this->postJson('/bfc/console/re-key', $body, ['Authorization' => $revoked->bearerHeader()]);

    $expiredResponse->assertUnauthorized();
    $revokedResponse->assertUnauthorized();

    // The refusals that MUST be indistinguishable are: no credential, an
    // unknown one, and a dead one. Distinguishing those would say whether
    // a presented secret ever named a real row.
    $unknown = $this->postJson('/bfc/console/re-key', $body, ['Authorization' => 'Bearer '.bin2hex(random_bytes(32))]);

    expect($expiredResponse->getContent())->toBe($anonymous->getContent())
        ->and($revokedResponse->getContent())->toBe($anonymous->getContent())
        ->and($unknown->getContent())->toBe($anonymous->getContent())
        ->and($unknown->getStatusCode())->toBe($anonymous->getStatusCode());

    // The ability failure is deliberately a 403, not folded into the 401
    // above: it is the package's published gate semantics on EVERY
    // operator route ("missing/unknown → 401, authenticated without the
    // ability → 403"), and the caller it separates is one that already
    // proved it holds a live credential — there is no existence to leak.
    expect($reader->credential->refresh()->revoked_at)->toBeNull();

    // Nothing was filed by any refusal.
    expect(ConsoleKey::query()->count())->toBe(0);

    // And the admin-equivalent break-glass reaches the verb.
    $breakGlass = keyCustodyOperator([OperatorAbility::ADMIN]);
    $this->postJson('/bfc/console/re-key', $body, ['Authorization' => $breakGlass->bearerHeader()])
        ->assertCreated();
});

// ------------------------------------------------------- AC7 — the audit

it('audits a successful re-key and a refused one with the actor typed (AC7)', function (): void {
    $rotator = keyCustodyRotator();
    $public = keyCustodyPublicKey(consoleKeypair());

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertCreated();

    $filed = CredentialAuditEvent::query()->where('event', LifecycleEventType::Delivered->value)->sole();
    $activated = CredentialAuditEvent::query()->where('event', LifecycleEventType::Activated->value)->sole();

    foreach ([$filed, $activated] as $event) {
        expect($event->actor_type)->toBe(AuditActorType::OperatorIntegration)
            ->and($event->actor_ref)->toBe($rotator->credential->id)
            ->and((string) $event->note)->toContain('k1')
            // Ids only: the delivered material never reaches the stream.
            ->and((string) $event->note)->not->toContain($public);
    }

    expect((string) $activated->note)->toContain('keys now verifying: k1');

    // A refused re-key — same key id, different material — is audited too.
    $this->postJson('/bfc/console/re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey(consoleKeypair()),
    ], ['Authorization' => $rotator->bearerHeader()])->assertStatus(409);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied->actor_ref)->toBe($rotator->credential->id)
        ->and((string) $denied->note)->toContain('console_key_id_in_use')
        ->and((string) $denied->note)->toContain('key id k1');
});

it('keeps a hostile key id out of the audit note (AC7)', function (): void {
    $rotator = keyCustodyRotator();

    $this->postJson('/bfc/console/re-key', [
        'key_id' => "k1\nfabricated: audit line",
        'public_key' => keyCustodyPublicKey(consoleKeypair()),
    ], ['Authorization' => $rotator->bearerHeader()])->assertStatus(422);

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', 'console%')
        ->sole();

    expect($denied->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and((string) $denied->note)->toContain('invalid_key_material')
        ->and((string) $denied->note)->not->toContain('fabricated');
});

// -------------------------------------------------- AC8 — rate limiting

it('rate-limits the re-key verb as an operator write (AC8)', function (): void {
    $rotator = keyCustodyRotator();
    $public = keyCustodyPublicKey(consoleKeypair());

    // The first delivery files; every repeat is a clean 409 — and each
    // one still spends limiter budget, because the throttle runs BEFORE
    // the gate and the controller.
    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertCreated();

    for ($i = 2; $i <= 60; $i++) {
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
            'Authorization' => $rotator->bearerHeader(),
        ])->assertStatus(409);
    }

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertStatus(429);

    // Bounded across addresses too: the per-credential bucket is the one
    // that makes a stolen credential bounded wherever it is replayed.
    $this->withServerVariables(['REMOTE_ADDR' => '10.9.9.9'])
        ->postJson('/bfc/console/re-key', ['key_id' => 'k2', 'public_key' => $public], [
            'Authorization' => $rotator->bearerHeader(),
        ])->assertStatus(429);

    expect(ConsoleKey::query()->count())->toBe(1);
});

// ---------------------------------------------------- AC9 — two transports

it('produces identical outcomes over HTTP and the artisan verb (AC9)', function (): void {
    $rotator = keyCustodyRotator();

    // IDENTICAL key material down each leg, under the one input a ring
    // cannot legitimately receive twice — the key id. Holding the
    // material fixed makes the TRANSPORT the only variable.
    $secret = consoleKeypair();
    $public = keyCustodyPublicKey($secret);

    $http = $this->postJson('/bfc/console/re-key', ['key_id' => 'parity-http', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ]);

    $http->assertCreated();

    $this->artisan('bfc:console:re-key', [
        'key_id' => 'parity-cli',
        'public_key' => $public,
        '--local' => true,
    ])->assertSuccessful();

    $viaHttp = ConsoleKey::query()->where('key_id', 'parity-http')->sole();
    $viaCli = ConsoleKey::query()->where('key_id', 'parity-cli')->sole();

    // Same stored form, same lifecycle state, both trusted.
    expect($viaCli->public_key)->toBe($viaHttp->public_key)
        ->and($viaCli->activated_at)->not->toBeNull()
        ->and($viaCli->retired_at)->toBeNull()
        ->and($viaHttp->retired_at)->toBeNull()
        ->and(keyCustodyActiveIds())->toBe(['parity-cli', 'parity-http']);

    // Same events, differing only in the actor each transport can
    // honestly name.
    foreach ([LifecycleEventType::Delivered, LifecycleEventType::Activated] as $event) {
        $notes = CredentialAuditEvent::query()->where('event', $event->value)->get();

        expect($notes)->toHaveCount(2)
            ->and($notes->pluck('actor_type')->all())
            ->toBe([AuditActorType::OperatorIntegration, AuditActorType::CliOperator]);
    }

    // Refusal parity: each transport refuses the other's key id with the
    // same server-authored message.
    $httpRefusal = $this->postJson('/bfc/console/re-key', ['key_id' => 'parity-cli', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ]);

    $httpRefusal->assertStatus(409);

    $this->artisan('bfc:console:re-key', [
        'key_id' => 'parity-http',
        'public_key' => $public,
        '--local' => true,
    ])->assertFailed()->expectsOutputToContain((string) $httpRefusal->json('message'));

    // …and refuse the same bad material with the same message.
    $httpInvalid = $this->postJson('/bfc/console/re-key', ['key_id' => 'parity-new', 'public_key' => 'not-a-key'], [
        'Authorization' => $rotator->bearerHeader(),
    ]);

    $httpInvalid->assertStatus(422);

    $this->artisan('bfc:console:re-key', [
        'key_id' => 'parity-new',
        'public_key' => 'not-a-key',
        '--local' => true,
    ])->assertFailed()->expectsOutputToContain((string) $httpInvalid->json('message'));

    // Neither refusal filed anything.
    expect(ConsoleKey::query()->count())->toBe(2);
});

it('refuses the artisan verb without --local, exactly as the credential verbs do (AC9)', function (): void {
    $this->artisan('bfc:console:re-key', [
        'key_id' => 'k1',
        'public_key' => keyCustodyPublicKey(consoleKeypair()),
    ])->assertFailed();

    expect(ConsoleKey::query()->count())->toBe(0);
});

// ------------------------------------------------- AC10 — idempotent-safe

it('refuses a repeated key id cleanly and never replaces the material behind it (AC10)', function (): void {
    $rotator = keyCustodyRotator();
    $original = keyCustodyPublicKey(consoleKeypair());
    $replacement = keyCustodyPublicKey(consoleKeypair());

    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $original], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertCreated();

    // Different material under a live key id: key substitution, refused.
    $substitution = $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $replacement], [
        'Authorization' => $rotator->bearerHeader(),
    ]);

    // A CLEAN refusal — the contract's prose shape, not a 500.
    $substitution->assertStatus(409)->assertJsonStructure(['message']);

    // The SAME material under the same key id is the same refusal: a key
    // id names one key for the life of the row, and the surface does not
    // special-case identical bytes.
    $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $original], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertStatus(409);

    // One row, original material intact.
    expect(ConsoleKey::query()->count())->toBe(1)
        ->and(ConsoleKey::query()->sole()->public_key)->toBe($original);

    // Same on the claim envelopes, and there the refusal takes the whole
    // claim with it.
    $this->postJson('/bfc/onboarding/exchange', [
        'token' => keyCustodyOnboardingCode('dupe@example.test'),
        'console_key' => ['key_id' => 'k1', 'public_key' => $replacement],
    ])->assertStatus(409)->assertJsonStructure(['message']);

    expect(ConsoleKey::query()->count())->toBe(1)
        ->and(ConsoleKey::query()->sole()->public_key)->toBe($original);
});

// ------------------------------------- AC11 — private material, honestly

it('refuses a 64-byte ed25519 SECRET key on both transports, and cannot detect a 32-byte seed (AC11)', function (): void {
    $rotator = keyCustodyRotator();

    // (1) DETECTABLE. The 64-byte expanded secret key is 128 hex
    // characters; nothing of that length stores, and the column is not
    // even wide enough to hold it.
    $secret = consoleKeypair();
    $secretKeyHex = bin2hex($secret->raw());

    expect(strlen($secretKeyHex))->toBe(128);

    $this->postJson('/bfc/console/re-key', ['key_id' => 'sk', 'public_key' => $secretKeyHex], [
        'Authorization' => $rotator->bearerHeader(),
    ])->assertStatus(422);

    $this->artisan('bfc:console:re-key', [
        'key_id' => 'sk',
        'public_key' => $secretKeyHex,
        '--local' => true,
    ])->assertFailed();

    $this->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode(),
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
    ], ['Authorization' => $rotator->bearerHeader()])->assertCreated();

    expect(ConsoleKey::query()->sole()->public_key)->toBe($seedThatPassesThePointTest);
});

it('never reveals key material back out of a delivery surface (AC11)', function (): void {
    $rotator = keyCustodyRotator();
    $public = keyCustodyPublicKey(consoleKeypair());

    $response = $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => $public], [
        'Authorization' => $rotator->bearerHeader(),
    ]);

    $response->assertCreated();

    expect($response->getContent())->not->toContain($public);

    $claim = $this->postJson('/bfc/ownership/claim', [
        'token' => keyCustodyClaimCode(),
        'console_key' => ['key_id' => 'k2', 'public_key' => keyCustodyPublicKey(consoleKeypair())],
    ]);

    $claim->assertCreated();

    expect((array) $claim->json('console_key'))
        ->toHaveKeys(['key_id', 'status', 'activated_at', 'active_key_ids'])
        ->and(array_keys((array) $claim->json('console_key')))
        ->not->toContain('public_key');
});
