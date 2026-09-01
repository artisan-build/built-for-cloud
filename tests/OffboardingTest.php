<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
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
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnifiedStoreDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
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

    // Database sessions are now refused by the global HTTP guard, so drive
    // the shared action directly to keep its database-session sweep covered.
    $result = app(OffboardSubject::class)(
        OffboardOptions::fromInput(['subject_type' => 'external_consumer', 'subject_ref' => 'acme']),
        AuditActor::operatorIntegration('offboard-test'),
    );

    expect($result->applied)->toBeTrue()
        ->and($result->fullyContained())->toBeTrue();

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
    $first->assertOk()->assertExactJson(['offboarded' => true, 'fully_contained' => true]);

    $auditAfterFirst = CredentialAuditEvent::query()->count();

    $second = $this->postJson('/bfc/subjects/offboard', ['subject_type' => 'external_consumer', 'subject_ref' => 'acme'], $headers);
    $second->assertOk()->assertExactJson(['offboarded' => true, 'fully_contained' => true]);

    // No duplicate deaths, no duplicate subject event; the sensitive-read
    // / denial channels are untouched by a clean repeat too.
    expect(CredentialAuditEvent::query()->count())->toBe($auditAfterFirst)
        ->and(OffboardedSubject::query()->where('user_id', OffboardedSubject::SUBJECT_ROW)->count())->toBe(1);

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
    offboardViaHttp($event('evt-offboard-6', 6))->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => true]);

    expect($credential->credential->refresh()->revoked_at)->toBeNull()
        ->and(OffboardedSubject::query()->count())->toBe(0);

    // A NEWER event (version 8): same uniform acknowledgement, and the
    // containment ran — including the invite history's pending code.
    offboardViaHttp($event('evt-offboard-8', 8))->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => true]);

    expect($credential->credential->refresh()->revoked_at)->not->toBeNull()
        ->and(Invitation::query()->whereNull('accepted_at')->count())->toBe(0)
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'sponsor-login')))->toBeTrue();

    // A REPLAY of the applied event id: acknowledged, and a credential
    // minted since is untouched — the replay re-contains nothing.
    $later = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sponsor-login',
    ]);

    offboardViaHttp($event('evt-offboard-8', 8))->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => true]);

    expect($later->credential->refresh()->revoked_at)->toBeNull();

    // A partial event group refuses on both transports.
    offboardViaHttp([
        'subject_type' => 'external_consumer',
        'subject_ref' => 'sponsor-login',
        'integration_namespace' => 'github-sponsors',
    ])->assertStatus(422);
});

it('rejects an offboarded user on bfc.admin too, whatever session store kept the session alive (Fix 3)', function (): void {
    Route::middleware(['web', 'bfc.admin'])->get('/offboard-admin-guarded', fn (): array => ['ok' => true]);

    // The default array session store: the offboard transaction deletes
    // nothing here — the middleware check IS the containment.
    $user = User::query()->create([
        'name' => 'Admin Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);
    $user->forceFill(['is_admin' => true])->save();

    // Positive control: the admin passes the gate before containment.
    $this->actingAs($user)->get('/offboard-admin-guarded')->assertOk();

    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])->assertOk();

    // The surviving session presents itself on a bfc.admin-only route
    // (no bfc.auth stacked): rejected, and invalidated.
    $this->actingAs($user)->withSession(['residue' => 'still-here']);
    $this->get('/offboard-admin-guarded')->assertForbidden();

    expect(session()->has('residue'))->toBeFalse();
});

it('reports containment INCOMPLETE when the session store is outside the transaction\'s reach (Fix 3)', function (): void {
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    // (i) A non-enumerable driver (the array default): the response says
    // so instead of claiming a full sweep.
    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])
        ->assertOk()
        ->assertExactJson(['offboarded' => true, 'fully_contained' => false]);

    // (ii) A database store on ANOTHER connection: deferred is not done —
    // the step is named, and the after-commit delete's failure is logged
    // by exception class, never swallowed.
    config(['session.driver' => 'database', 'session.connection' => 'bogus_sessions_connection']);

    $records = [];

    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$records): void {
        $records[] = ['message' => $event->message, 'context' => $event->context];
    });

    $result = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => 'user_principal',
        'subject_ref' => 'person@example.com',
    ]));

    expect($result->fullyContained())->toBeFalse()
        ->and($result->incompleteSteps)->toBe(['sessions:deferred-other-connection'])
        ->and(OffboardedSubject::userIsOffboarded((string) $user->getKey()))->toBeTrue();

    $deferredFailure = array_values(array_filter(
        $records,
        fn (array $record): bool => str_contains($record['message'], 'could not delete sessions'),
    ));

    expect($deferredFailure)->toHaveCount(1)
        ->and($deferredFailure[0]['context'])->toBe(['exception' => InvalidArgumentException::class]);
});

it('reports an incomplete containment step through the integration acknowledgement too (r3 fold)', function (): void {
    // A bound user makes the sessions step run; the array session driver
    // (the test default) makes it unreachable — the forced compensation
    // gap the direct path already reports.
    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sponsor-y',
        'user_id' => (string) $user->getKey(),
    ]);

    // The applying integration event acks — but NOT clean: the
    // containment status rides the acknowledgement.
    offboardViaHttp([
        'integration_namespace' => 'ns-y',
        'event_id' => 'evt-y-1',
        'entitlement_version' => 1,
        'external_subject' => 'sponsor-y',
    ])->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => false]);

    // The CLI transport warns identically on its applying event.
    $this->artisan('bfc:subject:offboard', [
        '--integration-namespace' => 'ns-y',
        '--event-id' => 'evt-y-2',
        '--entitlement-version' => '2',
        '--external-subject' => 'sponsor-y',
        '--local' => true,
    ])
        ->expectsOutputToContain('Offboard event acknowledged.')
        ->expectsOutputToContain('Containment INCOMPLETE')
        ->assertSuccessful();

    // An IGNORED event ran no containment and acks clean — the only
    // uniformity trade is the incompleteness report itself.
    offboardViaHttp([
        'integration_namespace' => 'ns-y',
        'event_id' => 'evt-y-0',
        'entitlement_version' => 1,
        'external_subject' => 'sponsor-y',
    ])->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => true]);
});

it('makes a concurrent first offboard idempotent via the registry\'s unique subject key (Fix 6)', function (): void {
    // The schema constraint itself: two subject rows for the same
    // (subject_type, subject_ref) cannot both exist.
    DB::table('offboarded_subjects')->insert([
        'id' => (string) Str::uuid(),
        'subject_type' => 'external_consumer',
        'subject_ref' => 'race-proof',
        'user_id' => OffboardedSubject::SUBJECT_ROW,
        'offboarded_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(fn (): bool => DB::table('offboarded_subjects')->insert([
        'id' => (string) Str::uuid(),
        'subject_type' => 'external_consumer',
        'subject_ref' => 'race-proof',
        'user_id' => OffboardedSubject::SUBJECT_ROW,
        'offboarded_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]))->toThrow(UniqueConstraintViolationException::class);

    // The race, insert-between: a competing containment row lands AFTER
    // this offboard's already-contained read and BEFORE its insert. The
    // insert violates the unique key, the attempt rolls back whole, and
    // the bounded retry re-decides — never a 500, never a double write.
    $credential = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
    ]);

    $injected = false;

    DB::listen(function ($query) use (&$injected): void {
        if ($injected
            || ! str_contains($query->sql, 'offboarded_subjects')
            || ! str_starts_with(strtolower(ltrim($query->sql)), 'select')) {
            return;
        }

        $injected = true;

        DB::table('offboarded_subjects')->insert([
            'id' => (string) Str::uuid(),
            'subject_type' => 'external_consumer',
            'subject_ref' => 'acme',
            'user_id' => OffboardedSubject::SUBJECT_ROW,
            'offboarded_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    });

    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])
        ->assertOk()
        ->assertExactJson(['offboarded' => true, 'fully_contained' => true]);

    expect($injected)->toBeTrue()
        ->and(OffboardedSubject::query()->forSubject(new Subject(SubjectType::ExternalConsumer, 'acme'))
            ->where('user_id', OffboardedSubject::SUBJECT_ROW)->count())->toBe(1)
        ->and($credential->credential->refresh()->revoked_at)->not->toBeNull();
});

it('consumes a pending code linked to an already-revoked durable (Fix 7)', function (): void {
    // A credential someone revoked BEFORE the offboard, whose delivery
    // code is still outstanding (RevokeCredential's action consumes it,
    // but a raw revocation — or one from another path — does not).
    $revoked = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'acme',
        'revoked_at' => now()->subHour(),
    ]);

    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => null,
        'scope' => Scope::Consume->value,
        'token_hash' => hash('sha256', 'orphaned-code'),
        'durable_token_id' => $revoked->credential->id,
        'durable_store' => 'credentials',
        'expires_at' => now()->addHour(),
    ]);

    offboardViaHttp(['subject_type' => 'external_consumer', 'subject_ref' => 'acme'])->assertOk();

    expect($code->refresh()->consumed_at)->not->toBeNull();
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
    // Use the shared action because this fixture deliberately selects the
    // database session driver, which no HTTP request may now reach.
    $result = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'integration_namespace' => 'github-sponsors',
        'event_id' => 'evt-offboard-2',
        'entitlement_version' => 2,
        'external_subject' => 'sponsor-x',
    ]), AuditActor::operatorIntegration('offboard-test'));

    expect($result->acknowledged)->toBeTrue();

    // The created account is dead: registry row, sessions, reset tokens,
    // and any credential bound to them — full containment.
    expect(OffboardedSubject::userIsOffboarded((string) $created->getKey()))->toBeTrue()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0);

    config(['session.driver' => 'array']);

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

/**
 * Build an accepted-invitation chain hop0 → hop1 → … → hopN: user hop{i}
 * invited hop{i+1}, who accepted (used_by). Returns the created user ids
 * keyed by hop.
 *
 * @return array<int, string>
 */
function acceptedInvitationChain(int $hops): array
{
    $userIds = [];

    for ($i = 0; $i <= $hops; $i++) {
        $userIds[$i] = (string) DB::table('users')->insertGetId([
            'name' => 'Hop '.$i,
            'email' => 'hop'.$i.'@chain.test',
            'password' => 'irrelevant',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    $invitations = [];

    for ($i = 0; $i < $hops; $i++) {
        $invitations[] = [
            'id' => (string) Str::uuid(),
            'email' => 'hop'.$i.'@chain.test',
            'token' => hash('sha256', 'chain-invite-'.$i),
            'used_by' => $userIds[$i + 1],
            'accepted_at' => now(),
            'expires_at' => now()->addDay(),
            'created_at' => now(),
            'updated_at' => now(),
        ];
    }

    DB::table('invitations')->insert($invitations);

    return $userIds;
}

it('contains an arbitrarily deep accepted-invitation chain to its fixed point (r3 Fix 3)', function (): void {
    config(['session.driver' => 'database']);

    // Five hops — two beyond the old hard cap of three rounds.
    $chain = acceptedInvitationChain(5);
    $deepest = $chain[5];

    DB::table('sessions')->insert([
        'id' => 'deepest-session',
        'user_id' => $deepest,
        'payload' => 'payload',
        'last_activity' => now()->getTimestamp(),
    ]);

    DB::table('password_reset_tokens')->insert([
        'email' => 'hop5@chain.test',
        'token' => 'reset-hash',
        'created_at' => now(),
    ]);

    $deepestCredential = $this->mintCredential([
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'unrelated-app',
        'user_id' => $deepest,
    ]);

    $result = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => 'user_principal',
        'subject_ref' => 'hop0@chain.test',
    ]));

    // The DEEPEST hop is fully contained: registry, session, reset
    // token, and its bound credential — and the walk reports complete.
    expect($result->fullyContained())->toBeTrue()
        ->and(OffboardedSubject::userIsOffboarded($deepest))->toBeTrue()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $deepestCredential->plaintext()))->toBeNull();

    // Every intermediate hop too.
    foreach ($chain as $userId) {
        expect(OffboardedSubject::userIsOffboarded($userId) || $userId === $chain[0])->toBeTrue();
    }
});

it('terminates on a cyclic invitation chain (r3 Fix 3)', function (): void {
    config(['session.driver' => 'database']);

    // hop0 → hop1 → hop2, and hop2's invitation points BACK at hop0.
    $chain = acceptedInvitationChain(2);

    DB::table('invitations')->insert([
        'id' => (string) Str::uuid(),
        'email' => 'hop2@chain.test',
        'token' => hash('sha256', 'cycle-invite'),
        'used_by' => $chain[0],
        'accepted_at' => now(),
        'expires_at' => now()->addDay(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $result = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => 'user_principal',
        'subject_ref' => 'hop0@chain.test',
    ]));

    // A known user is never "new": the cycle closes the fixed point
    // instead of looping, and everyone in it is contained.
    expect($result->fullyContained())->toBeTrue()
        ->and(OffboardedSubject::userIsOffboarded($chain[0]))->toBeTrue()
        ->and(OffboardedSubject::userIsOffboarded($chain[2]))->toBeTrue();
});

it('surfaces the traversal ceiling and resumes from the registered frontier on re-run (r3 Fix 3)', function (): void {
    config(['session.driver' => 'database']);

    // A chain deeper than the ceiling: each round discovers one hop, so
    // hops past PRINCIPAL_TRAVERSAL_CEILING stay undiscovered on the
    // first run — and that is REPORTED, never silently truncated.
    $depth = OffboardSubject::PRINCIPAL_TRAVERSAL_CEILING + 5;
    $chain = acceptedInvitationChain($depth);
    $deepest = $chain[$depth];

    $first = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => 'user_principal',
        'subject_ref' => 'hop0@chain.test',
    ]));

    expect($first->fullyContained())->toBeFalse()
        ->and($first->incompleteSteps)->toContain('principals:traversal-ceiling')
        ->and(OffboardedSubject::userIsOffboarded($deepest))->toBeFalse();

    // The idempotent re-run seeds from the registered frontier and
    // finishes the walk: the deepest hop is contained and the result is
    // clean.
    $second = app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => 'user_principal',
        'subject_ref' => 'hop0@chain.test',
    ]));

    expect($second->fullyContained())->toBeTrue()
        ->and(OffboardedSubject::userIsOffboarded($deepest))->toBeTrue();
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
    ])->assertStatus(202)->assertExactJson(['accepted' => true, 'fully_contained' => true]);

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

it('refuses a decoy NAMESPACE for a subject gate-bound elsewhere (r3 Fix 2)', function (): void {
    $admin = ['Authorization' => 'Bearer '.auditAdminToken('ns-bind-admin')];

    // The victim's gate stands at version 7 under its REAL namespace.
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

    // The remaining cut the re-review named: a DECOY NAMESPACE with the
    // victim's external_subject at version 1 — its own gate is empty, but
    // the pair binding refuses it: nothing contained, recorded, or
    // advanced.
    offboardViaHttp([
        'integration_namespace' => 'decoy-ns',
        'event_id' => 'evt-dns-1',
        'entitlement_version' => 1,
        'external_subject' => 'victim',
    ])->assertStatus(422);

    expect($victim->credential->refresh()->revoked_at)->toBeNull()
        ->and(OffboardedSubject::query()->count())->toBe(0)
        ->and(IntegrationEntitlement::query()->where('integration_namespace', 'decoy-ns')->exists())->toBeFalse()
        ->and(IntegrationEvent::query()->where('event_id', 'evt-dns-1')->exists())->toBeFalse();

    // Binding, not ordering: even a HIGH version under the unbound
    // namespace refuses.
    offboardViaHttp([
        'integration_namespace' => 'decoy-ns',
        'event_id' => 'evt-dns-2',
        'entitlement_version' => 99,
        'external_subject' => 'victim',
    ])->assertStatus(422);

    expect($victim->credential->refresh()->revoked_at)->toBeNull();

    // The real namespace still gates exactly as before: old ignored…
    offboardViaHttp([
        'integration_namespace' => 'ns',
        'event_id' => 'evt-real-6',
        'entitlement_version' => 6,
        'external_subject' => 'victim',
    ])->assertStatus(202);

    expect($victim->credential->refresh()->revoked_at)->toBeNull();

    // …newer applies.
    offboardViaHttp([
        'integration_namespace' => 'ns',
        'event_id' => 'evt-real-8',
        'entitlement_version' => 8,
        'external_subject' => 'victim',
    ])->assertStatus(202);

    expect($victim->credential->refresh()->revoked_at)->not->toBeNull()
        ->and(OffboardedSubject::subjectIsOffboarded(new Subject(SubjectType::ExternalConsumer, 'victim')))->toBeTrue();

    // A subject with no history ANYWHERE can be gate-established by any
    // authorized namespace — the refusal is a binding rule, not a lockout.
    $fresh = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'fresh-subject',
    ]);

    offboardViaHttp([
        'integration_namespace' => 'brand-new-ns',
        'event_id' => 'evt-fresh-1',
        'entitlement_version' => 1,
        'external_subject' => 'fresh-subject',
    ])->assertStatus(202);

    expect($fresh->credential->refresh()->revoked_at)->not->toBeNull();
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

it('never resolves an offboarded principal anywhere — the resolver is the containment choke point (r3 Fix 1)', function (): void {
    // A unified-store declaration so the verify surface resolves against
    // `credentials`, with its first-use burn.
    config(['built-for-cloud.credentials.declaration' => UnifiedStoreDeclaration::class]);

    $user = User::query()->create([
        'name' => 'Person',
        'email' => 'person@example.com',
        'password' => 'irrelevant',
    ]);

    // Bound to the user under an UNRELATED subject: the sweep never
    // touches this row — only the registry can kill it — and its linked
    // claim code is still awaiting its first-use burn.
    $minted = $this->mintCredential([
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'unrelated-app',
        'user_id' => (string) $user->getKey(),
    ]);

    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => null,
        'scope' => Scope::Consume->value,
        'token_hash' => hash('sha256', 'linked-first-use-code'),
        'durable_token_id' => $minted->credential->id,
        'durable_store' => 'credentials',
        'expires_at' => now()->addHour(),
    ]);

    // Positive control: before containment the secret validates (the
    // resolver path — no usage recorded, nothing burned).
    expect(auth('bfc')->validate(['secret' => $minted->plaintext()]))->toBeTrue();

    offboardViaHttp(['subject_type' => 'user_principal', 'subject_ref' => 'person@example.com'])->assertOk();

    // 1 — the raw resolver: null, though the row itself is unrevoked.
    expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $minted->plaintext()))->toBeNull()
        ->and($minted->credential->refresh()->revoked_at)->toBeNull();

    // 2 — CredentialGuard::validate(), a path the per-gate patch missed.
    expect(auth('bfc')->validate(['secret' => $minted->plaintext()]))->toBeFalse();

    // 3 — the onboarding verify surface, the other missed path: refused
    // as an unknown secret, and the FIRST-USE BURN DOES NOT FIRE — the
    // linked code is untouched, no usage stamped.
    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$minted->plaintext()])
        ->assertStatus(404)
        ->assertJsonPath('error', 'code_not_found');

    expect($code->refresh()->consumed_at)->toBeNull()
        ->and($minted->credential->refresh()->last_used_at)->toBeNull();

    // 4 — a credential minted AFTER containment for the offboarded
    // subject itself resolves to null too: the registry keys on the
    // subject, so the choke point catches rows born after the sweep.
    $postMint = $this->mintCredential([
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'person@example.com',
    ]);

    expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $postMint->plaintext()))->toBeNull();

    // The three gates (auth:bfc, the operator gate, the hmac verifier)
    // keep their own coverage in the Fix 2 tests below — all riding this
    // one resolver check now, except the hmac verifier's key selection,
    // which never resolves by secret and keeps its load-bearing check.
});

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
