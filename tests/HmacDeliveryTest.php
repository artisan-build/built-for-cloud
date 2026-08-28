<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The hmac delivery surfaces (PRD 1.21 / D9 amendment 3, REVERSED by
 * SEC-V3-01): mint born pending, claim-link delivery to an outside
 * counterparty, and the exchange that delivers key material but NEVER
 * activates — an intercepted link yields a key that signs nothing and
 * verifies nothing, and live signing state is untouched.
 */

/**
 * Mint an hmac key with claim-code delivery for a subject.
 *
 * @return array{Credential, string} the pending row and the claim code
 */
function hmacClaimMint(string $subjectRef = 'webhook-client', int $ttl = 3600): array
{
    $result = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, $subjectRef),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => $ttl]),
    );

    /** @var Credential $credential */
    $credential = Credential::query()->findOrFail($result->summary->id);

    assert($result->secret !== null);

    return [$credential, $result->secret->reveal()];
}

/**
 * @return array{Authorization: string}
 */
function hmacAdminHeaders(): array
{
    return ['Authorization' => 'Bearer '.auditAdminToken('hmac-admin-'.bin2hex(random_bytes(4)))];
}

function bindBurnMode(BurnMode $mode): void
{
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class($mode) implements CredentialDeclaration, DeclaresBurnMode
    {
        public function __construct(private readonly BurnMode $mode) {}

        public function burnMode(): BurnMode
        {
            return $this->mode;
        }

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }
    });
}

// ------------------------------------------------------- mint deliveries

it('mints a claim-code delivery when a code ttl is chosen: the key stays undelivered until exchange', function (): void {
    [$credential, $claimCode] = hmacClaimMint();

    expect($credential->status)->toBe(CredentialStatus::Pending)
        ->and($credential->delivered_at)->toBeNull()
        ->and($claimCode)->toMatch('/^[0-9a-f]{64}$/');

    /** @var OnboardingToken $code */
    $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->firstOrFail();

    expect($code->durableStore()->value)->toBe('credentials')
        ->and($code->consumed_at)->toBeNull();
});

it('bounds the hmac claim-code ttl exactly like every other claim code', function (): void {
    app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'client'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 59]),
    );
})->throws(InvalidCredentialInput::class);

it('leaks the minted signing key into no side-effect channel on the reveal-once path', function (): void {
    /** @var MintResult $result */
    $result = $this->assertNoSecretLeakageOfMinted(
        fn (): MintResult => app(MintCredential::class)(
            new Subject(SubjectType::Application, 'postmaster'),
            MintOptions::fromInput(['kind' => 'hmac']),
        ),
        function (MintResult $result): string {
            assert($result->secret !== null);

            return $result->secret->reveal();
        },
    );

    expect($result->delivery)->toBe(DeliveryShape::SigningKey);
});

it('records issued + delivered on the reveal-once mint, and issued alone on the claim-code mint', function (): void {
    $direct = app(MintCredential::class)(
        new Subject(SubjectType::Application, 'postmaster'),
        MintOptions::fromInput(['kind' => 'hmac']),
    );

    expect(CredentialAuditEvent::query()->where('credential_id', $direct->summary->id)->pluck('event')->map(fn ($e) => $e->value)->sort()->values()->all())
        ->toBe(['delivered', 'issued']);

    [$viaCode] = hmacClaimMint();

    expect(CredentialAuditEvent::query()->where('credential_id', $viaCode->id)->pluck('event')->map(fn ($e) => $e->value)->all())
        ->toBe(['issued']);
});

// ------------------------------------- the exchange: delivers, never activates

it('exchanges the claim link into the pending key and changes NOTHING about signing state (locked AC 1 half)', function (): void {
    [$credential, $claimCode] = hmacClaimMint();

    /** @var TestResponse<Response> $response */
    $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $delivered = (string) $response->json('signing_key');

    expect($delivered)->toMatch('/^[0-9a-f]{64}$/')
        ->and($response->json('key_id'))->toBe($credential->id)
        ->and($response->json('kind'))->toBe('hmac')
        ->and($response->json('status'))->toBe('pending')
        ->and($response->json('durable_token'))->toBeNull();

    $credential->refresh();

    // Delivered — and STILL PENDING: the exchange never activates.
    expect($credential->status)->toBe(CredentialStatus::Pending)
        ->and($credential->activated_at)->toBeNull()
        ->and($credential->delivered_at)->not->toBeNull()
        ->and(app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version))
        ->toBe($delivered);

    // Audited: exchanged + delivered, attributed to the code bearer.
    $events = CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('actor_type', AuditActorType::CredentialHolder->value)
        ->pluck('event')
        ->map(fn ($e) => $e->value)
        ->sort()
        ->values()
        ->all();

    expect($events)->toBe(['delivered', 'exchanged']);
});

it('fails the legitimate receiver loudly with code_already_claimed after an interceptor exchanged an at_exchange link (locked AC 1)', function (): void {
    bindBurnMode(BurnMode::AtExchange);

    [$credential, $claimCode] = hmacClaimMint('intercepted-client');

    // The interceptor redeems the link: they learn a PENDING key only.
    $intercepted = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    expect($intercepted->json('status'))->toBe('pending');

    // The legitimate receiver's exchange: a loud already-claimed failure —
    // the detection signal the audit trail exists for.
    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');

    // Signing state: unchanged. The key is pending; nothing activated it.
    expect($credential->refresh()->status)->toBe(CredentialStatus::Pending)
        ->and($credential->activated_at)->toBeNull();
});

it('re-keys the pending row on a re-claim before activation, killing every prior delivery (locked AC 2)', function (): void {
    // The default first_use burn: activation is this kind's first
    // observable use, so the code stays presentable until then.
    [$credential, $claimCode] = hmacClaimMint('dropped-response-client');

    $first = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated()->json('signing_key');

    // The response was dropped; the receiver claims again: a USABLE fresh
    // delivery (make-before-break), same row, same code.
    $second = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated()->json('signing_key');

    expect($second)->toMatch('/^[0-9a-f]{64}$/')
        ->and($second)->not->toBe($first);

    $credential->refresh();

    // At most one live pending delivery per code: the stored ciphertext
    // now matches ONLY the second key — the first is dead bytes.
    expect(app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version))
        ->toBe($second)
        ->and(Credential::query()->where('kind', CredentialKind::Hmac->value)->count())->toBe(1)
        ->and($credential->status)->toBe(CredentialStatus::Pending);

    // The redelivery is audited as its own delivered event, named honestly.
    expect(CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::Delivered->value)
        ->count())->toBe(2)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $credential->id)
            ->where('note', 'like', 'redelivery%')
            ->exists())->toBeTrue();
});

it('refuses an expired hmac claim code with code_expired', function (): void {
    [, $claimCode] = hmacClaimMint('slow-client', 60);

    $this->travel(61)->seconds();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(410)
        ->assertJsonPath('error', 'code_expired');
});

it('stops delivering once the pending row is revoked: revocation consumed the code', function (): void {
    [$credential, $claimCode] = hmacClaimMint('offboarded-client');

    $this->deleteJson('/bfc/credentials/'.$credential->id, [], hmacAdminHeaders())->assertNoContent();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');
});

it('leaks the delivered signing key into no side-effect channel, revealing it exactly once in the exchange response', function (): void {
    [, $claimCode] = hmacClaimMint('leak-checked-client');

    /** @var TestResponse<Response> $response */
    $response = $this->assertNoSecretLeakageOfMinted(
        fn (): TestResponse => $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]),
        fn (TestResponse $response): string => (string) $response->json('signing_key'),
    );

    $response->assertCreated();

    $marker = (string) $response->json('signing_key');

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $marker);
});
