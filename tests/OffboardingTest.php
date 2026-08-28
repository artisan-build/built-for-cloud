<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * PRD 1.15 / SEC-V3-04 — the offboard verb: full account containment,
 * idempotent, one audit shape, version-gated for integration-driven
 * offboards, with the guard rejecting the contained principal on every
 * request thereafter.
 */
beforeEach(function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    Route::middleware('auth:bfc')->get('/offboard-guarded', fn (): array => ['ok' => true]);
    Route::middleware(['web', 'bfc.auth'])->get('/offboard-session-guarded', fn (): array => ['ok' => true]);
});

function offboardHeaders(): array
{
    $operator = test()->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'offboard-operator-'.bin2hex(random_bytes(4)),
        'abilities' => [OperatorAbility::SubjectOffboard->value],
    ]);

    return ['Authorization' => $operator->bearerHeader()];
}

function offboardViaHttp(array $body): TestResponse
{
    return test()->postJson('/bfc/subjects/offboard', $body, offboardHeaders());
}

it('contains the whole account in one action: every credential state, codes, invitations, reset tokens, sessions', function (): void {
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    // The subject's credentials, one per lifecycle state:
    $active = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
        'user_id' => (string) $user->getKey(),
    ]);

    $grace = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
        'expires_at' => now()->addMinutes(30),
    ]);
    // rotated_at is not fillable by design; stamp it the way the verb does.
    Credential::query()->whereKey($grace->credential->id)->update(['rotated_at' => now()]);

    $pendingBearer = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
        'status' => 'pending',
    ]);

    // A pending hmac signing key WITH its outstanding delivery claim code.
    $hmacResult = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'acme'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );

    // A subject-stamped legacy api_tokens row.
    $legacy = ApiToken::query()->create([
        'name' => 'legacy-acme',
        'token_hash' => hash('sha256', 'legacy-acme-secret'),
        'abilities' => [Scope::Consume->value],
        'subject_type' => SubjectType::ExternalConsumer->value,
        'subject_ref' => 'acme',
    ]);

    // The principal's pending claim code, invitation, reset token, session.
    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'person@example.com',
        'scope' => Scope::Consume->value,
        'token_hash' => hash('sha256', 'pending-code'),
        'expires_at' => now()->addHour(),
    ]);

    $invitation = Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'person@example.com',
        'token' => hash('sha256', 'pending-invite'),
        'expires_at' => now()->addDay(),
    ]);

    DB::table('password_reset_tokens')->insert([
        'email' => 'person@example.com',
        'token' => 'reset-token-hash',
        'created_at' => now(),
    ]);

    config(['session.driver' => 'database']);

    DB::table('sessions')->insert([
        'id' => 'pre-existing-session',
        'user_id' => $user->getKey(),
        'payload' => 'payload',
        'last_activity' => now()->getTimestamp(),
    ]);

    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])
        ->assertOk()
        ->assertExactJson(['offboarded' => true]);

    // Every credential in every lifecycle state is dead — active, grace,
    // pending bearer, pending hmac, and the legacy row.
    expect($active->credential->refresh()->revoked_at)->not->toBeNull()
        ->and($grace->credential->refresh()->revoked_at)->not->toBeNull()
        ->and($pendingBearer->credential->refresh()->revoked_at)->not->toBeNull()
        ->and(Credential::query()->findOrFail($hmacResult->summary->id)->revoked_at)->not->toBeNull()
        ->and($legacy->refresh()->revoked_at)->not->toBeNull();

    // Every outstanding code and invitation is consumed/canceled — the
    // hmac delivery code included — and the reset token and session are gone.
    expect(OnboardingToken::query()->whereNull('consumed_at')->count())->toBe(0)
        ->and($code->refresh()->consumed_at)->not->toBeNull()
        ->and($invitation->refresh()->accepted_at)->not->toBeNull()
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(DB::table('sessions')->count())->toBe(0);

    // The registry holds the subject and its bound user.
    expect(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'acme')))->toBeTrue()
        ->and(OffboardedSubject::userIsOffboarded((string) $user->getKey()))->toBeTrue();

    // One audit shape: a single subject-level `offboarded` event with the
    // acting operator principal, plus per-credential `revoked` events
    // with reason `offboarding` — ids only.
    $offboarded = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Offboarded->value)
        ->get();

    expect($offboarded)->toHaveCount(1)
        ->and($offboarded[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and((string) $offboarded[0]->note)->toContain('external_consumer:acme');

    $revoked = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('reason_code', 'offboarding')
        ->pluck('credential_id');

    expect($revoked)->toContain($active->credential->id)
        ->and($revoked)->toContain($grace->credential->id)
        ->and($revoked)->toContain($pendingBearer->credential->id)
        ->and($revoked)->toContain($hmacResult->summary->id)
        ->and($revoked)->toContain((string) $legacy->getKey());
});

it('rejects the offboarded principal on every subsequent request — the guard is the belt under the sweep', function (): void {
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    $offboardedSubjectCredential = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
        'user_id' => (string) $user->getKey(),
    ]);

    // A credential under a DIFFERENT subject, bound to the same user: the
    // sweep never touches it, the registry still kills it.
    $otherSubjectCredential = $this->mintCredential([
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'other-app',
        'user_id' => (string) $user->getKey(),
    ]);

    // Both authenticate before the offboard.
    $this->getJson('/offboard-guarded', ['Authorization' => $offboardedSubjectCredential->bearerHeader()])->assertOk();
    $this->getJson('/offboard-guarded', ['Authorization' => $otherSubjectCredential->bearerHeader()])->assertOk();

    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])->assertOk();

    // …and neither does afterward.
    $this->getJson('/offboard-guarded', ['Authorization' => $offboardedSubjectCredential->bearerHeader()])->assertUnauthorized();
    $this->getJson('/offboard-guarded', ['Authorization' => $otherSubjectCredential->bearerHeader()])->assertUnauthorized();

    // The untouched row proves it is the REGISTRY rejecting, not a revocation.
    expect($otherSubjectCredential->credential->refresh()->revoked_at)->toBeNull();
});

it('rejects and invalidates a surviving session — the stated compensation for stores outside the transaction', function (): void {
    // The array session driver stands in for every store the offboard
    // transaction cannot enumerate: nothing is deleted at offboard time,
    // and the registry + this middleware ARE the containment.
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])->assertOk();

    expect(OffboardedSubject::userIsOffboarded((string) $user->getKey()))->toBeTrue();

    // The pre-existing session presents itself: rejected, and invalidated.
    $this->actingAs($user)->withSession(['residue' => 'still-here']);

    $response = $this->get('/offboard-session-guarded');
    $response->assertForbidden();

    expect(session()->has('residue'))->toBeFalse();
});

it('is idempotent: a second offboard is a no-op with the same response shape and no new audit rows', function (): void {
    $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    // ONE operator credential for both calls, so the audit-count delta
    // isolates the offboard itself.
    $headers = offboardHeaders();

    $first = $this->postJson('/bfc/subjects/offboard', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme'], $headers);
    $first->assertOk()->assertExactJson(['offboarded' => true]);

    $auditAfterFirst = CredentialAuditEvent::query()->count();

    $second = $this->postJson('/bfc/subjects/offboard', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme'], $headers);
    $second->assertOk()->assertExactJson(['offboarded' => true]);

    // No duplicate deaths, no duplicate subject event; the sensitive-read
    // / denial channels are untouched by a clean repeat too.
    expect(CredentialAuditEvent::query()->count())->toBe($auditAfterFirst)
        ->and(OffboardedSubject::query()->whereNull('user_id')->count())->toBe(1);

    // The action reports the repeat honestly: applied=false, zero counts.
    $result = app(OffboardSubject::class)(
        OffboardOptions::fromInput([
            'subject_type' => 'external_consumer',
            'subject_ref' => 'acme',
        ]),
    );

    expect($result->applied)->toBeFalse()
        ->and($result->revokedCredentials)->toBe(0)
        ->and($result->consumedCodes)->toBe(0);
});

it('rides the shared version gate: a replayed or older offboard event is transactionally ignored', function (): void {
    // Advance the shared entitlement to version 7 through the INVITE verb
    // — one monotonic version per (namespace, subject) orders invites and
    // offboards together (the gate table PR8 built is shared).
    $admin = ['Authorization' => 'Bearer '.auditAdminToken('offboard-gate-admin')];

    $this->postJson('/bfc/invitations', [
        'email' => 'sponsor@example.com',
        'ttl_seconds' => 3600,
        'integration_namespace' => 'github-sponsors',
        'event_id' => 'evt-invite-7',
        'entitlement_version' => 7,
        'external_subject' => 'sponsor-login',
    ], $admin)->assertStatus(202);

    $credential = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sponsor-login',
    ]);

    $event = fn (string $id, int $version): array => [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'sponsor-login',
        'integration_namespace' => 'github-sponsors',
        'event_id' => $id,
        'entitlement_version' => $version,
        'external_subject' => 'sponsor-login',
    ];

    // An OLDER offboard event (version 6 < 7): uniform acknowledgement,
    // and NOTHING was contained.
    offboardViaHttp($event('evt-offboard-6', 6))->assertStatus(202)->assertExactJson(['accepted' => true]);

    expect($credential->credential->refresh()->revoked_at)->toBeNull()
        ->and(OffboardedSubject::query()->count())->toBe(0);

    // A NEWER event (version 8): same uniform acknowledgement, and the
    // containment ran — including the invite history's pending code.
    offboardViaHttp($event('evt-offboard-8', 8))->assertStatus(202)->assertExactJson(['accepted' => true]);

    expect($credential->credential->refresh()->revoked_at)->not->toBeNull()
        ->and(Invitation::query()->whereNull('accepted_at')->count())->toBe(0)
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'sponsor-login')))->toBeTrue();

    // A REPLAY of the applied event id: acknowledged, and a credential
    // minted since is untouched — the replay re-contains nothing.
    $later = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sponsor-login',
    ]);

    offboardViaHttp($event('evt-offboard-8', 8))->assertStatus(202)->assertExactJson(['accepted' => true]);

    expect($later->credential->refresh()->revoked_at)->toBeNull();

    // A partial event group refuses on both transports.
    offboardViaHttp([
        'subject_type' => 'external_consumer',
        'subject_ref' => 'sponsor-login',
        'integration_namespace' => 'github-sponsors',
    ])->assertStatus(422);
});

it('contains the accounts accepted integration invitations created (Fix 1)', function (): void {
    $admin = ['Authorization' => 'Bearer '.auditAdminToken('fix1-admin')];

    // The integration invited a human (version 1, addressed)…
    $this->postJson('/bfc/invitations', [
        'email' => 'sponsor-user@example.com',
        'ttl_seconds' => 3600,
        'integration_namespace' => 'github-sponsors',
        'event_id' => 'evt-invite-1',
        'entitlement_version' => 1,
        'external_subject' => 'sponsor-x',
    ], $admin)->assertStatus(202);

    // …and the invitee accepted: the ceremony created their account and
    // stamped the invitation's used_by (the state accept() leaves).
    $created = User::query()->create([
        'name' => 'Sponsor User',
        'email' => 'sponsor-user@example.com',
        'password' => 'irrelevant',
    ]);

    /** @var Invitation $invitation */
    $invitation = Invitation::query()->sole();
    $invitation->forceFill([
        'used_by' => (string) $created->getKey(),
        'accepted_at' => now(),
    ])->save();

    // The created user holds no credential at all — before Fix 1 nothing
    // linked them to the subject and everything below survived.
    config(['session.driver' => 'database']);

    DB::table('sessions')->insert([
        'id' => 'created-user-session',
        'user_id' => $created->getKey(),
        'payload' => 'payload',
        'last_activity' => now()->getTimestamp(),
    ]);

    DB::table('password_reset_tokens')->insert([
        'email' => 'sponsor-user@example.com',
        'token' => 'reset-hash',
        'created_at' => now(),
    ]);

    $boundCredential = $this->mintCredential([
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'unrelated-app',
        'user_id' => (string) $created->getKey(),
    ]);

    // The integration offboards its subject (version 2, target derived).
    offboardViaHttp([
        'integration_namespace' => 'github-sponsors',
        'event_id' => 'evt-offboard-2',
        'entitlement_version' => 2,
        'external_subject' => 'sponsor-x',
    ])->assertStatus(202);

    // The created account is dead: registry row, sessions, reset tokens,
    // and any credential bound to them — full containment.
    expect(OffboardedSubject::userIsOffboarded((string) $created->getKey()))->toBeTrue()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0);

    $this->getJson('/offboard-guarded', ['Authorization' => $boundCredential->bearerHeader()])->assertUnauthorized();

    // Another namespace's accepted invitee sharing the external-subject
    // string is NOT swept — the history is bound by namespace.
});

it('contains accounts created by accepted invitations addressed to the principal on the direct path (Fix 1)', function (): void {
    // The principal invited someone under their own address chain: an
    // invitation addressed to the principal's email, accepted, creating a
    // second account.
    User::query()->create([
        'name' => 'Principal',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    $created = User::query()->create([
        'name' => 'Invited',
        'email' => 'invited@example.com',
        'password' => 'irrelevant',
    ]);

    Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'person@example.com',
        'token' => hash('sha256', 'accepted-invite'),
        'used_by' => (string) $created->getKey(),
        'accepted_at' => now(),
        'expires_at' => now()->addDay(),
    ]);

    DB::table('password_reset_tokens')->insert([
        'email' => 'invited@example.com',
        'token' => 'reset-hash',
        'created_at' => now(),
    ]);

    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])->assertOk();

    // The email chain found the created account: person@ → invitation →
    // used_by → invited@'s reset token.
    expect(OffboardedSubject::userIsOffboarded((string) $created->getKey()))->toBeTrue()
        ->and(DB::table('password_reset_tokens')->count())->toBe(0);
});

it('binds the version gate to the offboard target: a decoy external subject cannot offboard a victim (Fix 4)', function (): void {
    // The victim's REAL gate stands at version 7 (advanced by an invite —
    // the shared monotonic history).
    $admin = ['Authorization' => 'Bearer '.auditAdminToken('gate-bind-admin')];

    $this->postJson('/bfc/invitations', [
        'ttl_seconds' => 3600,
        'integration_namespace' => 'ns',
        'event_id' => 'evt-invite-7',
        'entitlement_version' => 7,
        'external_subject' => 'victim',
    ], $admin)->assertStatus(202);

    $victim = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'victim',
    ]);

    // The attack the review named: an OLD event under a DECOY
    // external_subject (whose gate is empty, so version 1 would pass)
    // naming the victim in subject_ref. REFUSED as a mismatch — the
    // target is derived from the gated identity, never caller-supplied —
    // and nothing was contained, recorded, or advanced.
    offboardViaHttp([
        'subject_type' => 'external_consumer',
        'subject_ref' => 'victim',
        'integration_namespace' => 'ns',
        'event_id' => 'evt-decoy-1',
        'entitlement_version' => 1,
        'external_subject' => 'decoy',
    ])->assertStatus(422);

    expect($victim->credential->refresh()->revoked_at)->toBeNull()
        ->and(OffboardedSubject::query()->count())->toBe(0)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-decoy-1')->exists())->toBeFalse()
        ->and(IntegrationEntitlement::query()->where('external_subject', 'decoy')->exists())->toBeFalse();

    // A mismatched subject TYPE refuses identically.
    offboardViaHttp([
        'subject_type' => 'operator',
        'subject_ref' => 'victim',
        'integration_namespace' => 'ns',
        'event_id' => 'evt-decoy-1b',
        'entitlement_version' => 9,
        'external_subject' => 'victim',
    ])->assertStatus(422);

    // With the subject omitted, the decoy event targets the DECOY
    // identity itself — its own gate, its own containment, never the
    // victim's.
    offboardViaHttp([
        'integration_namespace' => 'ns',
        'event_id' => 'evt-decoy-2',
        'entitlement_version' => 1,
        'external_subject' => 'decoy',
    ])->assertStatus(202)->assertExactJson(['accepted' => true]);

    expect($victim->credential->refresh()->revoked_at)->toBeNull()
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'decoy')))->toBeTrue()
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'victim')))->toBeFalse();

    // Against the victim's real identity, an old version is still gated…
    offboardViaHttp([
        'integration_namespace' => 'ns',
        'event_id' => 'evt-old-victim',
        'entitlement_version' => 6,
        'external_subject' => 'victim',
    ])->assertStatus(202);

    expect($victim->credential->refresh()->revoked_at)->toBeNull();

    // …and only a genuinely newer event contains the victim — the gate
    // advances for the real bound identity alone.
    offboardViaHttp([
        'integration_namespace' => 'ns',
        'event_id' => 'evt-new-victim',
        'entitlement_version' => 8,
        'external_subject' => 'victim',
    ])->assertStatus(202);

    expect($victim->credential->refresh()->revoked_at)->not->toBeNull()
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'victim')))->toBeTrue()
        ->and((int) IntegrationEntitlement::query()->where('external_subject', 'victim')->value('entitlement_version'))->toBe(8);
});

it('runs the identical action on the CLI transport, --local required', function (): void {
    $credential = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    $this->artisan('bfc:subject:offboard', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])
        ->assertFailed();

    expect($credential->credential->refresh()->revoked_at)->toBeNull();

    $this->artisan('bfc:subject:offboard', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
        '--local' => true,
    ])
        ->expectsOutputToContain('Subject offboarded: 1 credential(s) revoked')
        ->assertSuccessful();

    expect($credential->credential->refresh()->revoked_at)->not->toBeNull();

    // The idempotent repeat, reported honestly.
    $this->artisan('bfc:subject:offboard', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
        '--local' => true,
    ])
        ->expectsOutputToContain('Subject already offboarded: 0 credential(s) revoked')
        ->assertSuccessful();

    // Junk subject types refuse identically to HTTP's 422.
    $this->artisan('bfc:subject:offboard', [
        'subject_type' => 'nonsense',
        'subject_ref' => 'acme',
        '--local' => true,
    ])->assertFailed();
});

/**
 * A valid signature header computed from a row's own stored key —
 * bypassing the signer's selection, for probing the verifier directly.
 */
function offboardSignedHeader(Credential $credential, string $body): string
{
    $envelope = new HmacEnvelope(
        keyId: $credential->id,
        eventType: 'test.event',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('app.url'),
    );

    $key = app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version);

    return $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $key));
}

it('rejects an offboarded bound user\'s operator credential on the operator gate itself (Fix 2)', function (): void {
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    // An operator credential under a DIFFERENT subject, bound to the user
    // — fully authorized on the operator gate before containment.
    $operator = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
        'user_id' => (string) $user->getKey(),
    ]);

    $this->getJson('/bfc/credentials', ['Authorization' => $operator->bearerHeader()])->assertOk();

    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])->assertOk();

    // The gate resolves credentials directly (not via auth:bfc), so this
    // is the gate's OWN registry check biting — the row itself was never
    // revoked (its subject was not the offboarded one).
    $this->getJson('/bfc/credentials', ['Authorization' => $operator->bearerHeader()])->assertUnauthorized();

    expect($operator->credential->refresh()->revoked_at)->toBeNull();

    // Mutations too: the same credential reaches no verb.
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'someone',
    ], ['Authorization' => $operator->bearerHeader()])->assertUnauthorized();
});

it('makes an offboarded subject\'s hmac key unselectable by the verifier, post-containment mints included (Fix 2)', function (): void {
    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])->assertOk();

    // Minted AFTER containment, fully active — the registry is keyed on
    // the subject, not the credential row, so this must still be dead.
    /** @var Credential $key */
    $key = Credential::factory()->hmac()->activated()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    $body = '{"event":"shipment.created"}';
    $header = offboardSignedHeader($key, $body);

    expect(fn (): Credential => app(HmacVerifier::class)->verify(
        new Subject(SubjectType::ExternalConsumer, 'acme'),
        $header,
        $body,
    ))->toThrow(HmacVerificationFailed::class);

    // Positive control: an identical key under a NON-offboarded subject
    // verifies — the rejection above is the registry, not the harness.
    /** @var Credential $controlKey */
    $controlKey = Credential::factory()->hmac()->activated()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'other',
    ]);

    $controlBody = '{"event":"shipment.created"}';
    $verified = app(HmacVerifier::class)->verify(
        new Subject(SubjectType::ExternalConsumer, 'other'),
        offboardSignedHeader($controlKey, $controlBody),
        $controlBody,
    );

    expect($verified->id)->toBe($controlKey->id);
});

it('rejects credentials minted AFTER containment for the offboarded subject on every gate (Fix 2)', function (): void {
    offboardViaHttp(['subject_type' => 'operator', 'subject_ref' => 'rogue-plane'])->assertOk();

    // A post-containment operator mint for the offboarded subject: active
    // row, admin-equivalent abilities — and still dead everywhere.
    $postMint = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'rogue-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    $this->getJson('/offboard-guarded', ['Authorization' => $postMint->bearerHeader()])->assertUnauthorized();
    $this->getJson('/bfc/credentials', ['Authorization' => $postMint->bearerHeader()])->assertUnauthorized();

    expect($postMint->credential->refresh()->revoked_at)->toBeNull();
});

it('consults the declaration verb matrix under the offboard verb', function (): void {
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
            return $verb !== CredentialVerb::Offboard;
        }
    });

    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])
        ->assertForbidden();

    expect(OffboardedSubject::query()->count())->toBe(0);
});
