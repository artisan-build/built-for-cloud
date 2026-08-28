<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The activate verb (PRD 1.21, SEC-V3-01): the SEPARATE
 * operator-authorized pending→active signing cutover. Exchange delivers;
 * only activation flips signing state. Locked ACs 3 (premature refused)
 * and 4 (duplicate semantics: refused, both transports) live here.
 */

/**
 * @return array{Authorization: string}
 */
function activationAdminHeaders(): array
{
    return ['Authorization' => 'Bearer '.auditAdminToken('activation-admin-'.bin2hex(random_bytes(4)))];
}

/**
 * A pending hmac key minted with claim delivery, optionally exchanged
 * (delivered).
 */
function pendingHmacKey(bool $exchanged, string $subjectRef = 'webhook-client'): Credential
{
    $result = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, $subjectRef),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );

    assert($result->secret !== null);
    $claimCode = $result->secret->reveal();

    if ($exchanged) {
        test()->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    }

    /** @var Credential */
    return Credential::query()->findOrFail($result->summary->id);
}

/**
 * The delivery fingerprint the receiver would quote back out-of-band:
 * the row's CURRENT one (SEC-V3-01 rework).
 */
function confirmedFingerprint(Credential $credential): string
{
    return (string) $credential->refresh()->delivery_fingerprint;
}

// ---------------------------------------------------------- the cutover

it('activates a delivered pending key: status flips, activated_at stamps, the claim code burns, the event records', function (): void {
    $credential = pendingHmacKey(exchanged: true);

    /** @var TestResponse<Response> $response */
    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => confirmedFingerprint($credential),
    ], activationAdminHeaders())
        ->assertOk();

    expect($response->json('credential.status'))->toBe('active')
        ->and($response->json('superseded_id'))->toBeNull()
        ->and($response->json('grace_ends_at'))->toBeNull();

    $credential->refresh();

    expect($credential->status)->toBe(CredentialStatus::Active)
        ->and($credential->activated_at)->not->toBeNull();

    // Activation is the first_use burn point: the code is consumed, and
    // the activated event carries its id (ids only, never values).
    /** @var OnboardingToken $code */
    $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->firstOrFail();

    expect($code->consumed_at)->not->toBeNull();

    /** @var CredentialAuditEvent $event */
    $event = CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::Activated->value)
        ->firstOrFail();

    expect($event->code_id)->toBe($code->id);
});

it('activates via the CLI with --local, refusing without it (the two-transport rule)', function (): void {
    $credential = pendingHmacKey(exchanged: true);
    $fingerprint = confirmedFingerprint($credential);

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--fingerprint' => $fingerprint]))->toBe(1);

    expect(Artisan::call('bfc:credential:activate', [
        'id' => $credential->id,
        '--fingerprint' => $fingerprint,
        '--local' => true,
    ]))->toBe(0)
        ->and(Artisan::output())->toContain('now the active signing key')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Active);
});

it('consumes the claim code at activation so the link in the inbox cannot re-deliver a LIVE key', function (): void {
    $result = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'client'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );

    assert($result->secret !== null);
    $claimCode = $result->secret->reveal();

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $this->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [
        'delivery_fingerprint' => (string) $exchange->json('delivery_fingerprint'),
    ], activationAdminHeaders())->assertOk();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');
});

it('activates a reveal-once-minted key without any exchange: the mint response WAS the delivery, its fingerprint included', function (): void {
    $result = app(MintCredential::class)(
        new Subject(SubjectType::Application, 'postmaster'),
        MintOptions::fromInput(['kind' => 'hmac']),
    );

    expect($result->deliveryFingerprint)->toMatch('/^[0-9a-f]{16}$/');

    $this->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [
        'delivery_fingerprint' => (string) $result->deliveryFingerprint,
    ], activationAdminHeaders())
        ->assertOk()
        ->assertJsonPath('credential.status', 'active');
});

it('carries no secret in the activation response or CLI output on any channel', function (): void {
    $credential = pendingHmacKey(exchanged: true);
    $storedKey = app(HmacKeyring::class)
        ->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version);

    /** @var TestResponse<Response> $response */
    $response = $this->assertNoSecretLeakage($storedKey, fn (): TestResponse => $this->postJson(
        '/bfc/credentials/'.$credential->id.'/activate',
        ['delivery_fingerprint' => confirmedFingerprint($credential)],
        activationAdminHeaders(),
    ));

    $response->assertOk();

    $this->assertResponseCarriesNoSecret($response, $storedKey);
});

// --------------------------------------------- premature activation (AC 3)

it('refuses premature activation of an undelivered key, naming why, on both transports (locked AC 3)', function (): void {
    $credential = pendingHmacKey(exchanged: false);

    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => 'deadbeefdeadbeef',
    ], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('has not been delivered');

    expect(Artisan::call('bfc:credential:activate', [
        'id' => $credential->id,
        '--fingerprint' => 'deadbeefdeadbeef',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('has not been delivered')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});

it('requires the delivery fingerprint identically on both transports: an id alone cannot say which delivery was confirmed', function (): void {
    $credential = pendingHmacKey(exchanged: true);

    $http = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
        ->assertUnprocessable();

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--local' => true]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    expect($cliMessage)->toBe((string) $http->json('message'))
        ->and($cliMessage)->toContain('requires the delivery fingerprint')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});

// -------------------------------- the intercepted re-key (SEC-V3-01 rework)

it('refuses the stale confirmation after an interceptor re-claims, so the attacker\'s re-keyed material never activates (the headline AC)', function (): void {
    // A subject with a live production signing key, mid-rotation.
    $productionMint = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'prod-client'),
        MintOptions::fromInput(['kind' => 'hmac']),
    );
    $this->postJson('/bfc/credentials/'.$productionMint->summary->id.'/activate', [
        'delivery_fingerprint' => (string) $productionMint->deliveryFingerprint,
    ], activationAdminHeaders())->assertOk();

    $rotate = $this->postJson('/bfc/credentials/'.$productionMint->summary->id.'/rotate', [
        'code_ttl_seconds' => 3600,
    ], activationAdminHeaders())->assertCreated();

    $pendingId = (string) $rotate->json('credential.id');
    $claimCode = (string) $rotate->json('delivery.claim_code');

    // The RECEIVER claims: installs K1, quotes fingerprint F1 back, and
    // the operator now holds the confirmation "F1 is installed".
    $legitimate = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    $confirmedF1 = (string) $legitimate->json('delivery_fingerprint');
    $installedK1 = (string) $legitimate->json('signing_key');

    // The INTERCEPTOR re-claims the same link before the operator
    // activates: the pending row is re-keyed to the attacker's K2/F2.
    $intercepted = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    $attackerF2 = (string) $intercepted->json('delivery_fingerprint');
    $attackerK2 = (string) $intercepted->json('signing_key');

    expect($attackerF2)->not->toBe($confirmedF1)
        ->and($attackerK2)->not->toBe($installedK1);

    // The operator's STALE confirmation must refuse: activating with F1
    // would otherwise cut signing over to K2 — key material the
    // confirmer never saw. The attacker's key never becomes active.
    $stale = $this->postJson('/bfc/credentials/'.$pendingId.'/activate', [
        'delivery_fingerprint' => $confirmedF1,
    ], activationAdminHeaders())->assertStatus(409);

    expect((string) $stale->json('message'))->toContain('not credential '.$pendingId.'\'s current delivery');

    /** @var Credential $pendingRow */
    $pendingRow = Credential::query()->findOrFail($pendingId);

    expect($pendingRow->status)->toBe(CredentialStatus::Pending)
        ->and($pendingRow->activated_at)->toBeNull()
        // F2 is indeed the row's current delivery — the mismatch was real.
        ->and((string) $pendingRow->delivery_fingerprint)->toBe($attackerF2)
        // Production signing state is untouched: the old key still signs.
        ->and(app(HmacSigner::class)
            ->sign(new Subject(SubjectType::ExternalConsumer, 'prod-client'), 'body', 'evt'))
        ->toContain('key='.$productionMint->summary->id);

    // Recovery: the legitimate receiver re-claims — which RE-KEYS again,
    // killing the attacker's K2 — installs K3, and confirms F3. That
    // confirmation matches the row's current delivery and activates.
    $reclaimed = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    $confirmedF3 = (string) $reclaimed->json('delivery_fingerprint');
    $installedK3 = (string) $reclaimed->json('signing_key');

    $this->postJson('/bfc/credentials/'.$pendingId.'/activate', [
        'delivery_fingerprint' => $confirmedF3,
    ], activationAdminHeaders())->assertOk();

    // The now-active key is the receiver's K3 — never the attacker's K2.
    /** @var Credential $activeRow */
    $activeRow = Credential::query()->findOrFail($pendingId);

    expect($activeRow->status)->toBe(CredentialStatus::Active)
        ->and(app(HmacKeyring::class)
            ->decrypt((string) $activeRow->secret_ciphertext, $activeRow->secret_key_version))
        ->toBe($installedK3)
        ->and($installedK3)->not->toBe($attackerK2);
});

// --------------------------------------------- duplicate activation (AC 4)

it('refuses a duplicate activation — deliberately not idempotent — identically on both transports (locked AC 4)', function (): void {
    $credential = pendingHmacKey(exchanged: true);
    $fingerprint = confirmedFingerprint($credential);

    $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => $fingerprint,
    ], activationAdminHeaders())->assertOk();

    $http = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => $fingerprint,
    ], activationAdminHeaders())
        ->assertStatus(409);

    expect(Artisan::call('bfc:credential:activate', [
        'id' => $credential->id,
        '--fingerprint' => $fingerprint,
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    expect($cliMessage)->toBe((string) $http->json('message'))
        ->and($cliMessage)->toContain('already active')
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $credential->id)
            ->where('event', LifecycleEventType::Activated->value)
            ->count())->toBe(1);
});

// ----------------------------------------------------------- other refusals

it('refuses to activate any non-hmac kind: no other kind has the transition', function (): void {
    $bearer = Credential::factory()->create();

    $response = $this->postJson('/bfc/credentials/'.$bearer->id.'/activate', [
        'delivery_fingerprint' => 'deadbeefdeadbeef',
    ], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('hmac');
});

it('refuses to activate revoked and expired rows, naming the state', function (): void {
    $revoked = Credential::factory()->hmac()->delivered()->revoked()->create();
    $expired = Credential::factory()->hmac()->delivered()->expired()->create();

    $headers = activationAdminHeaders();

    expect((string) $this->postJson('/bfc/credentials/'.$revoked->id.'/activate', [
        'delivery_fingerprint' => confirmedFingerprint($revoked),
    ], $headers)
        ->assertStatus(409)->json('message'))->toContain('revoked');

    expect((string) $this->postJson('/bfc/credentials/'.$expired->id.'/activate', [
        'delivery_fingerprint' => confirmedFingerprint($expired),
    ], $headers)
        ->assertStatus(409)->json('message'))->toContain('expired');
});

it('404s an unknown id on HTTP and fails with the same story on the CLI', function (): void {
    $this->postJson('/bfc/credentials/does-not-exist/activate', [
        'delivery_fingerprint' => 'deadbeefdeadbeef',
    ], activationAdminHeaders())->assertNotFound();

    expect(Artisan::call('bfc:credential:activate', [
        'id' => 'does-not-exist',
        '--fingerprint' => 'deadbeefdeadbeef',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('No credential');
});

it('consults the activate matrix verb — its own authority, refusable while rotate stays allowed — on both transports', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return $verb !== CredentialVerb::Activate;
        }
    });

    $credential = pendingHmacKey(exchanged: true);
    $fingerprint = confirmedFingerprint($credential);

    $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => $fingerprint,
    ], activationAdminHeaders())
        ->assertForbidden()
        ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'activate'));

    expect(Artisan::call('bfc:credential:activate', [
        'id' => $credential->id,
        '--fingerprint' => $fingerprint,
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('activate')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});

it('pauses activation while an APP_KEY rewrap is in progress, with the retry-later error (SEC-V3-08)', function (): void {
    $credential = pendingHmacKey(exchanged: true);
    $fingerprint = confirmedFingerprint($credential);

    // Stage the rotation: new APP_KEY, old key readable in previous_keys.
    $oldKey = (string) config('app.key');
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
        'delivery_fingerprint' => $fingerprint,
    ], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('bfc:hmac:rewrap')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});
