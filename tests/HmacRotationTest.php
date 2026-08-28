<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * hmac rotation (D6 point 6 / D9, replacing PR7's explicit stub): rotate
 * mints the replacement PENDING while the old key keeps signing; delivery
 * installs it receiver-side; ACTIVATION cuts signing over; the old key
 * verifies through grace from activation and dies at grace end —
 * immediately under emergency. Locked AC 10 (the dance end-to-end,
 * lineage + events, cutover completion for a failed hmac cutover) and the
 * end-to-end half of AC 5 live here.
 */

/**
 * @return array{Authorization: string}
 */
function hmacRotationAdminHeaders(): array
{
    return ['Authorization' => 'Bearer '.auditAdminToken('hmac-rotation-admin-'.bin2hex(random_bytes(4)))];
}

function hmacRotationSubject(string $ref = 'webhook-client'): Subject
{
    return new Subject(SubjectType::ExternalConsumer, $ref);
}

/**
 * An ACTIVE hmac signing key produced by the real verbs: reveal-once
 * mint, then activation.
 */
function mintedActiveHmacKey(string $subjectRef = 'webhook-client', array $options = []): Credential
{
    $result = app(MintCredential::class)(
        hmacRotationSubject($subjectRef),
        MintOptions::fromInput(['kind' => 'hmac', ...$options]),
    );

    test()->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [], hmacRotationAdminHeaders())->assertOk();

    /** @var Credential */
    return Credential::query()->findOrFail($result->summary->id);
}

function signedHeaderFor(Credential $credential, string $body): string
{
    $key = app(HmacKeyring::class)
        ->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version);

    $envelope = new HmacEnvelope(
        keyId: $credential->id,
        eventType: 'test.event',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('app.url'),
    );

    return $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $key));
}

// ------------------------------------------------- the dance, end to end

it('walks the whole rotation dance: pending → deliver → activate → grace → old dead, lineage and events asserted (locked ACs 5 + 10)', function (): void {
    $old = mintedActiveHmacKey();
    $body = 'payload';

    // Rotate: the replacement is born PENDING behind a claim code; the
    // old key is stamped but keeps signing, unbounded.
    /** @var TestResponse<Response> $rotate */
    $rotate = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [
        'code_ttl_seconds' => 3600,
    ], hmacRotationAdminHeaders())->assertCreated();

    $newId = (string) $rotate->json('credential.id');
    $claimCode = (string) $rotate->json('delivery.claim_code');

    expect($rotate->json('delivery.shape'))->toBe('signing_key_code')
        ->and($rotate->json('credential.status'))->toBe('pending')
        ->and($rotate->json('superseded_id'))->toBe($old->id);

    $old->refresh();

    expect($old->rotated_at)->not->toBeNull()
        ->and($old->expires_at)->toBeNull()
        ->and($old->status)->toBe(CredentialStatus::Active);

    // Between rotate and activate: the OLD key verifies; the pending
    // replacement verifies nothing.
    expect(app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($old, $body), $body)->id)
        ->toBe($old->id);

    /** @var Credential $pendingNew */
    $pendingNew = Credential::query()->findOrFail($newId);

    expect(fn () => app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($pendingNew, $body), $body))
        ->toThrow(HmacVerificationFailed::class);

    // Delivery installs it receiver-side.
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();

    expect($exchange->json('key_id'))->toBe($newId)
        ->and((string) $exchange->json('signing_key'))->toMatch('/^[0-9a-f]{64}$/');

    // Activation cuts over: the response names the superseded key and its
    // grace horizon.
    $activate = $this->postJson('/bfc/credentials/'.$newId.'/activate', [], hmacRotationAdminHeaders())->assertOk();

    expect($activate->json('superseded_id'))->toBe($old->id)
        ->and($activate->json('grace_ends_at'))->not->toBeNull();

    $old->refresh();

    expect($old->expires_at)->not->toBeNull()
        ->and($old->expires_at->diffInSeconds(now()->addHour(), true))->toBeLessThan(5.0);

    // Through grace: BOTH verify, the key id selecting (AC 5, end to end).
    $new = $pendingNew->refresh();

    expect(app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($old, $body), $body)->id)->toBe($old->id)
        ->and(app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($new, $body), $body)->id)->toBe($newId);

    // After grace: only the new — the old died by its own expiry.
    $this->travel(61)->minutes();

    expect(fn () => app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($old, $body), $body))
        ->toThrow(HmacVerificationFailed::class);

    expect(app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($new, $body), $body)->id)->toBe($newId);

    // Lineage + events: issued/delivered/exchanged/activated on the new
    // key; rotated on the old, carrying old → new supersession.
    $newEvents = CredentialAuditEvent::query()->where('credential_id', $newId)
        ->pluck('event')->map(fn ($e) => $e->value)->sort()->values()->all();

    expect($newEvents)->toBe(['activated', 'delivered', 'exchanged', 'issued']);

    /** @var CredentialAuditEvent $lineage */
    $lineage = CredentialAuditEvent::query()
        ->where('credential_id', $old->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->firstOrFail();

    expect($lineage->superseded_by_credential_id)->toBe($newId);
});

it('rotates with the reveal-once delivery when no code ttl is chosen: this response IS the delivery', function (): void {
    $old = mintedActiveHmacKey();

    /** @var TestResponse<Response> $rotate */
    $rotate = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())->assertCreated();

    $newId = (string) $rotate->json('credential.id');

    expect($rotate->json('delivery.shape'))->toBe('signing_key')
        ->and($rotate->json('delivery.key_id'))->toBe($newId)
        ->and((string) $rotate->json('delivery.signing_key'))->toMatch('/^[0-9a-f]{64}$/');

    /** @var Credential $new */
    $new = Credential::query()->findOrFail($newId);

    expect($new->delivered_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()->where('credential_id', $newId)
            ->pluck('event')->map(fn ($e) => $e->value)->sort()->values()->all())
        ->toBe(['delivered', 'issued']);

    // Delivered means activatable: the dance can complete.
    $this->postJson('/bfc/credentials/'.$newId.'/activate', [], hmacRotationAdminHeaders())->assertOk();
});

it('preserves the exact ability set, subject binding, name and expiry on the pending replacement', function (): void {
    $result = app(MintCredential::class)(
        hmacRotationSubject('scoped-client'),
        MintOptions::fromInput([
            'kind' => 'hmac',
            'name' => 'webhooks',
            'abilities' => ['consume'],
            'user_id' => '42',
            'expires_at' => now()->addDays(30)->toIso8601String(),
        ]),
    );

    $this->postJson('/bfc/credentials/'.$result->summary->id.'/activate', [], hmacRotationAdminHeaders())->assertOk();

    /** @var TestResponse<Response> $rotate */
    $rotate = $this->postJson('/bfc/credentials/'.$result->summary->id.'/rotate', [], hmacRotationAdminHeaders())->assertCreated();

    /** @var Credential $replacement */
    $replacement = Credential::query()->findOrFail((string) $rotate->json('credential.id'));

    expect($replacement->subject_ref)->toBe('scoped-client')
        ->and($replacement->name)->toBe('webhooks')
        ->and($replacement->abilities)->toBe(['consume'])
        ->and($replacement->user_id)->toBe('42')
        ->and($replacement->expires_at?->toDateString())->toBe(now()->addDays(30)->toDateString())
        ->and($replacement->status)->toBe(CredentialStatus::Pending);
});

it('rotates via the CLI, revealing the claim code once and naming the pending state', function (): void {
    $old = mintedActiveHmacKey();

    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $old->id,
        '--code-ttl' => '3600',
        '--local' => true,
    ]))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('Claim code - shown once')
        ->and($output)->toContain('PENDING')
        ->and($output)->toContain('until activation');
});

// ----------------------------------------------------------- emergency

it('kills the old key immediately under emergency while the replacement is still pending: the stated signing outage (locked AC 5)', function (): void {
    $old = mintedActiveHmacKey();
    $body = 'payload';

    /** @var TestResponse<Response> $rotate */
    $rotate = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [
        'emergency' => true,
        'code_ttl_seconds' => 3600,
    ], hmacRotationAdminHeaders())->assertCreated();

    // The compromised old key verifies NOTHING, now.
    expect(fn () => app(HmacVerifier::class)->verify(hmacRotationSubject(), signedHeaderFor($old->refresh(), $body), $body))
        ->toThrow(HmacVerificationFailed::class);

    // The replacement is pending: nothing signs until the dance finishes
    // — exactly what emergency has always meant, an immediate outage.
    expect($rotate->json('credential.status'))->toBe('pending');
});

// ------------------------------------- re-rotation and cutover completion

it('refuses to re-rotate a stamped source while its replacement awaits activation, pointing at the activate verb, on both transports', function (): void {
    $old = mintedActiveHmacKey();

    $rotate = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())->assertCreated();
    $newId = (string) $rotate->json('credential.id');

    $http = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())
        ->assertStatus(409);

    expect(Artisan::call('bfc:credential:rotate', ['id' => $old->id, '--local' => true]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    expect($cliMessage)->toBe((string) $http->json('message'))
        ->and($cliMessage)->toContain('PENDING activation')
        ->and($cliMessage)->toContain($newId)
        // Nothing minted, nothing retired: the old key still signs.
        ->and(Credential::query()->count())->toBe(2)
        ->and($old->refresh()->expires_at)->toBeNull();
});

it('completes a failed hmac cutover through the rotate verb: retirement only, nothing minted (locked AC 10)', function (): void {
    $old = mintedActiveHmacKey();

    $rotate = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())->assertCreated();
    $newId = (string) $rotate->json('credential.id');

    $this->postJson('/bfc/credentials/'.$newId.'/activate', [], hmacRotationAdminHeaders())->assertOk();

    // Failure path B's shape: the activation committed but the old row's
    // grace-bounding write was lost — stamped, successor active, nothing
    // bounding the old key.
    Credential::query()->whereKey($old->id)->update(['expires_at' => null]);

    /** @var TestResponse<Response> $completion */
    $completion = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())
        ->assertOk();

    expect($completion->json('completed_cutover'))->toBeTrue()
        ->and($completion->json('credential.id'))->toBe($newId)
        ->and($completion->json('delivery.shape'))->toBe('none')
        ->and(Credential::query()->count())->toBe(2);

    $old->refresh();

    expect($old->expires_at)->not->toBeNull()
        ->and($old->expires_at->diffInSeconds(now()->addHour(), true))->toBeLessThan(5.0);
});

// --------------------------------------------------- rewrap pause (AC 6)

it('pauses hmac rotation while an APP_KEY rewrap is in progress, identically on both transports (SEC-V3-08)', function (): void {
    $old = mintedActiveHmacKey();

    $oldKey = (string) config('app.key');
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    config()->set('app.previous_keys', [$oldKey]);

    $http = $this->postJson('/bfc/credentials/'.$old->id.'/rotate', [], hmacRotationAdminHeaders())
        ->assertStatus(409);

    expect(Artisan::call('bfc:credential:rotate', ['id' => $old->id, '--local' => true]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    expect($cliMessage)->toBe((string) $http->json('message'))
        ->and($cliMessage)->toContain('bfc:hmac:rewrap')
        ->and($old->refresh()->rotated_at)->toBeNull();
});

it('still refuses to rotate a pending hmac row: delivery re-claims or a fresh mint are the paths, never rotation', function (): void {
    $pending = Credential::factory()->hmac()->delivered()->create();

    $response = $this->postJson('/bfc/credentials/'.$pending->id.'/rotate', [], hmacRotationAdminHeaders())
        ->assertStatus(409);

    expect((string) $response->json('message'))->toContain('pending');
});
