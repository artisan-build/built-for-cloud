<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesHmacSubjects;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * The sign/verify pair over the canonical envelope (PRD 1.21,
 * SEC-V3-07). Locked ACs here: 5 (old + new verify through grace, key id
 * selecting; after grace only the new; emergency kills immediately),
 * 7 (the envelope rejections, boundary- and window-tested), 8 (verifier
 * selection is server-derived — a crafted header naming another
 * subject's key id cannot verify), 9 (signing uses only the active key;
 * a subject with only pending keys cannot sign).
 */
function hmacSubject(string $ref = 'acme'): Subject
{
    return new Subject(SubjectType::ExternalConsumer, $ref);
}

/**
 * An ACTIVE signing key for a subject, exactly as the verbs leave one.
 */
function activeKeyFor(string $subjectRef, ?string $signingKey = null): Credential
{
    return Credential::factory()->hmac($signingKey)->activated()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => $subjectRef,
    ]);
}

/**
 * Compute a valid header for a body USING A ROW'S OWN STORED KEY —
 * bypassing the signer's selection, for crafting adversarial headers.
 */
function headerSignedBy(Credential $credential, string $body, ?string $audience = null, ?int $timestamp = null, ?string $nonce = null): string
{
    $envelope = new HmacEnvelope(
        keyId: $credential->id,
        eventType: 'test.event',
        timestamp: $timestamp ?? now()->getTimestamp(),
        nonce: $nonce ?? bin2hex(random_bytes(16)),
        audience: $audience ?? (string) config('app.url'),
    );

    $key = app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version);

    return $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $key));
}

// ------------------------------------------------------------ round trip

it('signs with the active key and verifies through the canonical envelope, stamping last_used_at', function (): void {
    $credential = activeKeyFor('acme');
    $body = '{"event":"shipment.created"}';

    $header = app(HmacSigner::class)->sign(hmacSubject(), $body, 'shipment.created');

    expect($header)->toContain('key='.$credential->id)
        ->and($header)->toContain('alg=hmac-sha256');

    $verified = app(HmacVerifier::class)->verify(hmacSubject(), $header, $body);

    expect($verified->id)->toBe($credential->id)
        ->and($verified->refresh()->last_used_at)->not->toBeNull();
});

it('leaks no key material while signing: the header carries the key id, never the key', function (): void {
    $signingKey = bin2hex(random_bytes(32));
    activeKeyFor('acme', $signingKey);

    $header = $this->assertNoSecretLeakage(
        $signingKey,
        fn (): string => app(HmacSigner::class)->sign(hmacSubject(), 'body', 'evt'),
    );

    expect($header)->not->toContain($signingKey);
});

// --------------------------------------------------- signing refusals (AC 9)

it('refuses to sign for a subject whose only keys are pending, saying so explicitly (locked AC 9)', function (): void {
    Credential::factory()->hmac()->delivered()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'not-yet-activated',
    ]);

    try {
        app(HmacSigner::class)->sign(hmacSubject('not-yet-activated'), 'body', 'evt');
        $this->fail('Signing should have refused.');
    } catch (HmacSigningRefused $refused) {
        expect($refused->getMessage())->toContain('pending')
            ->and($refused->getMessage())->toContain('signs nothing until activated');
    }
});

it('refuses to sign for a subject with no hmac keys at all', function (): void {
    app(HmacSigner::class)->sign(hmacSubject('nobody'), 'body', 'evt');
})->throws(HmacSigningRefused::class, 'No ACTIVE hmac signing key');

it('keeps signing with the stamped old key between rotate and activate, then cuts over to the unstamped replacement', function (): void {
    // Between rotate and activate: old is stamped, replacement pending.
    $old = activeKeyFor('acme');
    Credential::query()->whereKey($old->id)->update(['rotated_at' => now()]);
    $pendingReplacement = Credential::factory()->hmac()->delivered()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    expect(app(HmacSigner::class)->sign(hmacSubject(), 'body', 'evt'))->toContain('key='.$old->id);

    // After activation: the unstamped active replacement owns signing.
    Credential::query()->whereKey($pendingReplacement->id)->update([
        'status' => 'active',
        'activated_at' => now(),
    ]);

    expect(app(HmacSigner::class)->sign(hmacSubject(), 'body', 'evt'))->toContain('key='.$pendingReplacement->id);
});

// ------------------------------------------- grace-window verification (AC 5)

it('verifies old AND new through the grace window by key id, only the new after it, and neither for a dead old key (locked AC 5)', function (): void {
    $body = 'payload';

    // The post-activation state: old stamped + grace-bounded, new active.
    $old = activeKeyFor('acme');
    Credential::query()->whereKey($old->id)->update([
        'rotated_at' => now(),
        'expires_at' => now()->addHour(),
    ]);
    $new = activeKeyFor('acme');

    $oldHeader = headerSignedBy($old->refresh(), $body);
    $newHeader = headerSignedBy($new, $body);

    // Through grace: BOTH verify, the key id selecting which key checks.
    expect(app(HmacVerifier::class)->verify(hmacSubject(), $oldHeader, $body)->id)->toBe($old->id)
        ->and(app(HmacVerifier::class)->verify(hmacSubject(), $newHeader, $body)->id)->toBe($new->id);

    // After grace: only the new — the old died by its own expiry.
    $this->travel(61)->minutes();

    $oldLate = headerSignedBy($old, $body);
    $newLate = headerSignedBy($new, $body);

    expect(fn (): Credential => app(HmacVerifier::class)->verify(hmacSubject(), $oldLate, $body))
        ->toThrow(HmacVerificationFailed::class);

    expect(app(HmacVerifier::class)->verify(hmacSubject(), $newLate, $body)->id)->toBe($new->id);
});

it('kills old-key verification immediately under an emergency retirement (locked AC 5)', function (): void {
    $old = activeKeyFor('acme');
    // The emergency shape: expiry collapsed to NOW.
    Credential::query()->whereKey($old->id)->update([
        'rotated_at' => now(),
        'expires_at' => now(),
    ]);

    $header = headerSignedBy($old->refresh(), 'body');

    app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
})->throws(HmacVerificationFailed::class);

// -------------------------------------------- envelope rejections (AC 7)

it('rejects the wrong audience', function (): void {
    $credential = activeKeyFor('acme');
    $header = headerSignedBy($credential, 'body', audience: 'https://somewhere-else.example');

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('wrong_audience');
    }
});

it('accepts a timestamp exactly at the tolerance bound and rejects one second past it (locked AC 7, boundary-tested)', function (): void {
    config()->set('built-for-cloud.hmac.timestamp_tolerance_seconds', 300);

    $credential = activeKeyFor('acme');

    $atBound = headerSignedBy($credential, 'body', timestamp: now()->getTimestamp() - 300);

    expect(app(HmacVerifier::class)->verify(hmacSubject(), $atBound, 'body')->id)->toBe($credential->id);

    $pastBound = headerSignedBy($credential, 'body', timestamp: now()->getTimestamp() - 301);

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $pastBound, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('stale_timestamp');
    }

    // The bound is two-sided: a future-dated message is just as stale.
    $future = headerSignedBy($credential, 'body', timestamp: now()->getTimestamp() + 301);

    expect(fn (): Credential => app(HmacVerifier::class)->verify(hmacSubject(), $future, 'body'))
        ->toThrow(HmacVerificationFailed::class);
});

it('rejects a replayed nonce inside the window, and a replay outliving the window on its timestamp (locked AC 7, window-tested)', function (): void {
    config()->set('built-for-cloud.hmac.timestamp_tolerance_seconds', 300);

    $credential = activeKeyFor('acme');
    $header = headerSignedBy($credential, 'body');

    expect(app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body')->id)->toBe($credential->id);

    // The exact bytes again, inside the window: the nonce is consumed.
    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('replayed_nonce');
    }

    // Past the 2x-tolerance window the nonce entry may be gone — but the
    // message is then stale by the timestamp rule: the window provably
    // covers the whole acceptance interval, so a replay NEVER verifies.
    $this->travel(601)->seconds();

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('stale_timestamp');
    }
});

it('rejects a replay at the exact edge of the acceptance window: the nonce entry outlives the last verifiable instant (rework Fix 2)', function (): void {
    config()->set('built-for-cloud.hmac.timestamp_tolerance_seconds', 300);

    $credential = activeKeyFor('acme');

    // The worst case: a future-dated message accepted at the EARLIEST
    // possible instant (ts = now + tolerance, inclusive). Its timestamp
    // stays verifiable until ts + tolerance = now + 2×tolerance — the
    // exact edge the nonce entry must still cover.
    $header = headerSignedBy($credential, 'body', timestamp: now()->getTimestamp() + 300);

    expect(app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body')->id)->toBe($credential->id);

    $this->travel(600)->seconds();

    // At exactly V + 2×tolerance the timestamp is still inside the
    // inclusive bound — and the replay must STILL be caught, by the
    // nonce, because the entry's TTL carries a margin past the window.
    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('replayed_nonce');
    }
});

it('caps accepted verifications per key per window, so one credential cannot fill the nonce store (rework Fix 3)', function (): void {
    config()->set('built-for-cloud.hmac.verification_rate_ceiling', 3);

    $credential = activeKeyFor('acme');
    $bystander = activeKeyFor('other');

    // Legitimate traffic under the ceiling verifies.
    foreach (range(1, 3) as $i) {
        $header = headerSignedBy($credential, 'body-'.$i);

        expect(app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body-'.$i)->id)->toBe($credential->id);
    }

    // The fourth ACCEPTED verification inside the window is refused —
    // before its nonce is stored, so the store never grows past the
    // ceiling for this key.
    $overflow = headerSignedBy($credential, 'body-4');

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $overflow, 'body-4');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('rate_limited');
    }

    // The ceiling is PER KEY: another credential's traffic is untouched.
    $bystanderHeader = headerSignedBy($bystander, 'body');

    expect(app(HmacVerifier::class)->verify(hmacSubject('other'), $bystanderHeader, 'body')->id)->toBe($bystander->id);
});

it('spends no rate budget on replays: one captured envelope replayed N times cannot rate-limit the legitimate holder (rework attempt-3 Fix 2)', function (): void {
    config()->set('built-for-cloud.hmac.verification_rate_ceiling', 3);

    $credential = activeKeyFor('acme');

    // One genuine verification: one nonce slot, one budget unit.
    $captured = headerSignedBy($credential, 'body-1');

    expect(app(HmacVerifier::class)->verify(hmacSubject(), $captured, 'body-1')->id)->toBe($credential->id);

    // The attacker replays the captured envelope five times: every one
    // is rejected as a replay, and NONE spends a budget unit.
    foreach (range(1, 5) as $attempt) {
        try {
            app(HmacVerifier::class)->verify(hmacSubject(), $captured, 'body-1');
            $this->fail('Replay '.$attempt.' should have refused.');
        } catch (HmacVerificationFailed $failed) {
            expect($failed->reason)->toBe('replayed_nonce');
        }
    }

    // The legitimate holder's remaining budget (2 of 3) is intact.
    foreach ([2, 3] as $i) {
        $fresh = headerSignedBy($credential, 'body-'.$i);

        expect(app(HmacVerifier::class)->verify(hmacSubject(), $fresh, 'body-'.$i)->id)->toBe($credential->id);
    }

    // And the ceiling still binds a genuine flood of NEW nonces.
    $overflow = headerSignedBy($credential, 'body-4');

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $overflow, 'body-4');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('rate_limited');
    }
});

it('rejects a leading-zero timestamp: the canonical wire form is injective (rework Fix 6)', function (): void {
    $credential = activeKeyFor('acme');
    $valid = headerSignedBy($credential, 'body');

    preg_match('/ts=(\d+)/', $valid, $matches);

    foreach (['0'.$matches[1], '000'.$matches[1]] as $padded) {
        $tampered = str_replace('ts='.$matches[1], 'ts='.$padded, $valid);

        try {
            app(HmacVerifier::class)->verify(hmacSubject(), $tampered, 'body');
            $this->fail('Verification should have refused ts='.$padded);
        } catch (HmacVerificationFailed $failed) {
            expect($failed->reason)->toBe('malformed_header');
        }
    }
});

it('rejects an unknown key id with the same indistinct answer as every selection miss', function (): void {
    activeKeyFor('acme');
    $ghost = Credential::factory()->hmac()->activated()->make([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    // A header naming a key id no row carries, signed with... anything.
    $envelope = new HmacEnvelope(
        keyId: (string) Str::uuid(),
        eventType: 'evt',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('app.url'),
    );
    $header = $envelope->headerValue(hash_hmac('sha256', $envelope->canonical('body'), 'whatever'));

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('unusable_key');
    }
});

it('rejects algorithm substitution: the verifier pins hmac-sha256 and negotiates nothing (locked AC 7)', function (): void {
    $credential = activeKeyFor('acme');
    $valid = headerSignedBy($credential, 'body');

    foreach (['none', 'hmac-sha1', 'hmac-sha512'] as $substituted) {
        $tampered = str_replace('alg=hmac-sha256', 'alg='.$substituted, $valid);

        try {
            app(HmacVerifier::class)->verify(hmacSubject(), $tampered, 'body');
            $this->fail('Verification should have refused alg='.$substituted);
        } catch (HmacVerificationFailed $failed) {
            expect($failed->reason)->toBe('algorithm_rejected');
        }
    }
});

it('rejects a pending key\'s signature: a pending key verifies nothing (locked AC 7)', function (): void {
    $pending = Credential::factory()->hmac()->delivered()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    // Validly signed with the pending key's own material — still refused:
    // selection admits active-or-grace only.
    $header = headerSignedBy($pending, 'body');

    try {
        app(HmacVerifier::class)->verify(hmacSubject(), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('unusable_key');
    }
});

it('rejects a tampered body and a tampered envelope field under a valid signature', function (): void {
    $credential = activeKeyFor('acme');
    $header = headerSignedBy($credential, 'body');

    expect(fn (): Credential => app(HmacVerifier::class)->verify(hmacSubject(), $header, 'tampered-body'))
        ->toThrow(HmacVerificationFailed::class);

    $retargeted = str_replace('event=test.event', 'event=other.event', $header);

    expect(fn (): Credential => app(HmacVerifier::class)->verify(hmacSubject(), $retargeted, 'body'))
        ->toThrow(HmacVerificationFailed::class);
});

it('rejects malformed headers outright', function (): void {
    activeKeyFor('acme');

    foreach ([
        '',
        'garbage',
        'v2,alg=hmac-sha256,key=x,event=e,ts=1,nonce='.str_repeat('a', 16).',aud=a,sig='.str_repeat('0', 64),
        'v1,key=x,alg=hmac-sha256,event=e,ts=1,nonce='.str_repeat('a', 16).',aud=a,sig='.str_repeat('0', 64),
    ] as $malformed) {
        try {
            app(HmacVerifier::class)->verify(hmacSubject(), $malformed, 'body');
            $this->fail('Verification should have refused: '.$malformed);
        } catch (HmacVerificationFailed $failed) {
            expect($failed->reason)->toBe('malformed_header');
        }
    }
});

// ------------------------------------- server-derived selection (AC 8)

it('cannot verify another subject\'s key id however valid the signature: selection is server-derived (locked AC 8)', function (): void {
    activeKeyFor('victim');
    $attacker = activeKeyFor('attacker');

    // The attacker signs a message VALIDLY under their own key, but the
    // server derived subject "victim" for this request: the crafted
    // header's key id cannot reach across subjects.
    $header = headerSignedBy($attacker, 'body');

    try {
        app(HmacVerifier::class)->verify(hmacSubject('victim'), $header, 'body');
        $this->fail('Verification should have refused.');
    } catch (HmacVerificationFailed $failed) {
        expect($failed->reason)->toBe('unusable_key');
    }
});

// ------------------------------------------------------------ middleware

it('gates a route through bfc.hmac: the declaration derives the subject server-side, valid signatures pass, everything else is one 401', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements CredentialDeclaration, ResolvesHmacSubjects
    {
        public function resolveHmacSubject(Request $request): ?Subject
        {
            // Server-derived: the route names the tenant; the header is
            // never consulted.
            $client = $request->route('client');

            return is_string($client) ? new Subject(SubjectType::ExternalConsumer, $client) : null;
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

    Route::post('/hooks/{client}', function (Request $request): array {
        return ['ok' => true, 'credential' => $request->attributes->get('bfc.hmac_credential_id')];
    })->middleware('bfc.hmac');

    $acme = activeKeyFor('acme');
    activeKeyFor('other-tenant');

    $body = '{"n":1}';

    // A valid signature for the derived subject passes; the verified key
    // id rides the request attributes.
    $this->call('POST', '/hooks/acme', server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => headerSignedBy($acme, $body),
        'CONTENT_TYPE' => 'application/json',
    ], content: $body)
        ->assertOk()
        ->assertJsonPath('credential', $acme->id);

    // No header, a garbage header, and a cross-subject header: ONE
    // uniform 401, no oracle.
    $this->postJson('/hooks/acme', ['n' => 1])->assertUnauthorized();

    $this->call('POST', '/hooks/acme', server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => 'garbage',
        'CONTENT_TYPE' => 'application/json',
    ], content: $body)->assertUnauthorized();

    $other = Credential::query()->where('subject_ref', 'other-tenant')->firstOrFail();

    $this->call('POST', '/hooks/acme', server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => headerSignedBy($other, $body),
        'CONTENT_TYPE' => 'application/json',
    ], content: $body)->assertUnauthorized();
});

it('answers the uniform 401 through bfc.hmac when the key STATE is broken — an unreadable ring key is no oracle and no 500 (rework Fix 7)', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements CredentialDeclaration, ResolvesHmacSubjects
    {
        public function resolveHmacSubject(Request $request): ?Subject
        {
            return new Subject(SubjectType::ExternalConsumer, 'acme');
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

    Route::post('/hooks-broken-ring', fn (): array => ['ok' => true])->middleware('bfc.hmac');

    $credential = activeKeyFor('acme');
    $header = headerSignedBy($credential, 'body');

    // The row's ciphertext key leaves the ring AFTER the header was
    // computed: verification now hits HmacKeyUnreadable.
    Credential::query()->whereKey($credential->id)->update(['secret_key_version' => 'feedfacefeedface']);

    $this->call('POST', '/hooks-broken-ring', server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $header,
    ], content: 'body')
        ->assertUnauthorized()
        ->assertJsonPath('message', 'The request signature could not be verified.');
});

it('normalizes EVERY keyring failure to the uniform 401 — unsupported cipher, malformed ring entry, wrong-length key, absent APP_KEY (rework attempt-3 Fix 3)', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements CredentialDeclaration, ResolvesHmacSubjects
    {
        public function resolveHmacSubject(Request $request): ?Subject
        {
            return new Subject(SubjectType::ExternalConsumer, 'acme');
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

    Route::post('/hooks-ring-states', fn (): array => ['ok' => true])->middleware('bfc.hmac');

    $credential = activeKeyFor('acme');

    $healthy = [
        'key' => config('app.key'),
        'cipher' => config('app.cipher'),
        'previous' => config('app.previous_keys'),
    ];

    $breakages = [
        'unsupported cipher' => function (): void {
            config()->set('app.cipher', 'ROT13');
        },
        'absent APP_KEY' => function (): void {
            config()->set('app.key', '');
        },
        'malformed base64 ring entry, row on a departed version' => function () use ($credential): void {
            config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
            config()->set('app.previous_keys', ['base64:!!!not-base64!!!']);
            // The row's version now names neither the new primary nor a
            // parseable ring entry.
            Credential::query()->whereKey($credential->id)->update(['secret_key_version' => 'feedfacefeedface']);
        },
        'wrong-length ring key whose fingerprint matches' => function () use ($credential): void {
            config()->set('app.key', 'short-key');
            Credential::query()->whereKey($credential->id)->update([
                'secret_key_version' => HmacKeyring::fingerprint('short-key'),
            ]);
        },
    ];

    foreach ($breakages as $state => $break) {
        // Restore a healthy ring, craft a FRESH valid header (a reused
        // one would trip the nonce instead and mask the case), then
        // break the ring the stated way.
        config()->set('app.key', $healthy['key']);
        config()->set('app.cipher', $healthy['cipher']);
        config()->set('app.previous_keys', $healthy['previous']);
        Credential::query()->whereKey($credential->id)->update([
            'secret_key_version' => app(HmacKeyring::class)->writeVersion(),
        ]);

        $header = headerSignedBy($credential->refresh(), 'body');

        $break();

        // The uniform refusal — never a 500, never a key-state detail.
        $this->call('POST', '/hooks-ring-states', server: [
            'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $header,
        ], content: 'body')
            ->assertUnauthorized()
            ->assertJsonPath('message', 'The request signature could not be verified.');
    }
});

it('fails closed through bfc.hmac when the declaration cannot derive subjects at all', function (): void {
    Route::post('/hooks-undeclared', fn (): array => ['ok' => true])->middleware('bfc.hmac');

    $credential = activeKeyFor('acme');

    $this->call('POST', '/hooks-undeclared', server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => headerSignedBy($credential, 'body'),
    ], content: 'body')->assertUnauthorized();
});
