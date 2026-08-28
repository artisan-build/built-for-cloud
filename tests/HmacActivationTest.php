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

// ---------------------------------------------------------- the cutover

it('activates a delivered pending key: status flips, activated_at stamps, the claim code burns, the event records', function (): void {
    $credential = pendingHmacKey(exchanged: true);

    /** @var TestResponse<Response> $response */
    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
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

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id]))->toBe(1);

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--local' => true]))->toBe(0)
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

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    $this->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [], activationAdminHeaders())->assertOk();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');
});

it('activates a reveal-once-minted key without any exchange: the mint response WAS the delivery', function (): void {
    $result = app(MintCredential::class)(
        new Subject(SubjectType::Application, 'postmaster'),
        MintOptions::fromInput(['kind' => 'hmac']),
    );

    $this->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [], activationAdminHeaders())
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
        [],
        activationAdminHeaders(),
    ));

    $response->assertOk();

    $this->assertResponseCarriesNoSecret($response, $storedKey);
});

// --------------------------------------------- premature activation (AC 3)

it('refuses premature activation of an undelivered key, naming why, on both transports (locked AC 3)', function (): void {
    $credential = pendingHmacKey(exchanged: false);

    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('has not been delivered');

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--local' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('has not been delivered')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});

// --------------------------------------------- duplicate activation (AC 4)

it('refuses a duplicate activation — deliberately not idempotent — identically on both transports (locked AC 4)', function (): void {
    $credential = pendingHmacKey(exchanged: true);

    $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())->assertOk();

    $http = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
        ->assertStatus(409);

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--local' => true]))->toBe(1);

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

    $response = $this->postJson('/bfc/credentials/'.$bearer->id.'/activate', [], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('hmac');
});

it('refuses to activate revoked and expired rows, naming the state', function (): void {
    $revoked = Credential::factory()->hmac()->delivered()->revoked()->create();
    $expired = Credential::factory()->hmac()->delivered()->expired()->create();

    $headers = activationAdminHeaders();

    expect((string) $this->postJson('/bfc/credentials/'.$revoked->id.'/activate', [], $headers)
        ->assertStatus(409)->json('message'))->toContain('revoked');

    expect((string) $this->postJson('/bfc/credentials/'.$expired->id.'/activate', [], $headers)
        ->assertStatus(409)->json('message'))->toContain('expired');
});

it('404s an unknown id on HTTP and fails with the same story on the CLI', function (): void {
    $this->postJson('/bfc/credentials/does-not-exist/activate', [], activationAdminHeaders())->assertNotFound();

    expect(Artisan::call('bfc:credential:activate', ['id' => 'does-not-exist', '--local' => true]))->toBe(1)
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

    $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
        ->assertForbidden()
        ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'activate'));

    expect(Artisan::call('bfc:credential:activate', ['id' => $credential->id, '--local' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('activate')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});

it('pauses activation while an APP_KEY rewrap is in progress, with the retry-later error (SEC-V3-08)', function (): void {
    $credential = pendingHmacKey(exchanged: true);

    // Stage the rotation: new APP_KEY, old key readable in previous_keys.
    $oldKey = (string) config('app.key');
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    $response = $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [], activationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('bfc:hmac:rewrap')
        ->and($credential->refresh()->status)->toBe(CredentialStatus::Pending);
});
