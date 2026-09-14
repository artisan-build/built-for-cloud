<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Symfony\Component\Process\Process;

/**
 * The personal-credentials surface (PRD 1.17): an authenticated human
 * manages their OWN machine credentials, over the SAME store and the same
 * PR6 verbs the operator surface runs.
 *
 * The security property every test below circles: the subject is derived
 * SERVER-SIDE from the authenticated session (SEC-V3-07) and never from
 * client input, and cross-user access is denied by any crafted input.
 */
uses(RefreshDatabase::class, DetectsSecretLeaks::class);

beforeEach(function (): void {
    // The fixtures' per-test knobs; reset so nothing bleeds between tests.
    SelfServiceDeclaration::$unsupported = [];
    SelfServicePolicyDeclaration::$abilities = [];
    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer];

    config(['built-for-cloud.credentials.declaration' => SelfServiceDeclaration::class]);
});

/**
 * Two stand-in MCP tool routes behind the per-tool ability primitive
 * (PRD 1.10) — the concrete thing a self-service credential must not be
 * able to reach by asking for the ability.
 */
function personalMcpRoutes(): void
{
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    Route::post('/mcp/purge', fn (): array => ['purged' => true])
        ->middleware('bfc.ability:'.OperatorAbility::McpAdmin->value);

    Route::post('/mcp/status', fn (): array => ['ok' => true])
        ->middleware('bfc.ability:'.OperatorAbility::McpRead->value);
}

function personalUser(string $email): User
{
    /** @var User */
    return User::query()->create([
        'name' => $email,
        'email' => $email,
        'password' => bcrypt('secret-'.bin2hex(random_bytes(4))),
    ]);
}

/**
 * The subject the fixture declaration derives for a given user — spelled
 * out here so every assertion states the SERVER-SIDE answer explicitly
 * rather than reading it back off the row it is supposed to be checking.
 */
function personalSubjectRef(User $user): string
{
    return 'user:'.$user->getAuthIdentifier();
}

function personalCredentialFor(User $user, array $attributes = []): Credential
{
    /** @var Credential */
    return Credential::query()->create(array_merge([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => personalSubjectRef($user),
        'user_id' => (string) $user->getAuthIdentifier(),
        'name' => 'laptop',
        'status' => CredentialStatus::Active,
        'secret_hash' => hash('sha256', 'seeded-'.bin2hex(random_bytes(8))),
    ], $attributes));
}

/** @return array{key_id: string, signing_key: string} */
function p5dMintActivatedPersonalHmac(User $user): array
{
    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);
    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];

    $mint = test()->actingAsVersioned($user, 'web')->postJson('/bfc/me/credentials', [
        'name' => 'p5d-managed-signing',
        'kind' => CredentialKind::Hmac->value,
    ])->assertCreated();
    $keyId = (string) $mint->json('delivery.key_id');

    test()->postJson('/bfc/credentials/'.$keyId.'/activate', [
        'delivery_fingerprint' => (string) $mint->json('delivery.delivery_fingerprint'),
    ], [
        'Authorization' => 'Bearer '.auditOperatorCredential(
            'p5d-hmac-activation',
            [OperatorAbility::CredentialRotate->value],
        ),
    ])->assertOk();

    return [
        'key_id' => $keyId,
        'signing_key' => (string) $mint->json('delivery.signing_key'),
    ];
}

function p5dConfigureManagedPersonalUser(User $user): ManagedAuthorityFixture
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => 'https://authority.example.test',
    ]);
    config(['built-for-cloud.managed.client_secret' => 'fixture-client-secret']);
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'p5d-personal-subject',
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 13,
        'managed_membership_response_sequence' => 13,
        'managed_membership_responded_at' => now(),
    ])->save();
    $fixture = new ManagedAuthorityFixture(
        'https://authority.example.test',
        'fixture-client-secret',
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
    );
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));

    return $fixture;
}

/** @param array{key_id: string, signing_key: string} $delivery */
function p5dSendPersonalHmac(User $user, array $delivery): TestResponse
{
    $body = '{"event":"p5d-managed-self-service"}';
    $envelope = new HmacEnvelope(
        keyId: $delivery['key_id'],
        eventType: 'self-service.test',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('built-for-cloud.hmac.audience'),
    );

    return test()->call('POST', '/p5d-personal-hmac/'.$user->getKey(), server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $envelope->headerValue(hash_hmac(
            'sha256',
            $envelope->canonical($body),
            $delivery['signing_key'],
        )),
        'CONTENT_TYPE' => 'application/json',
    ], content: $body);
}

// ------------------------------------------------------------ AC1: list mine

it('lists only the authenticated users own credentials', function (): void {
    $mine = personalUser('mine@example.test');
    $theirs = personalUser('theirs@example.test');

    $first = personalCredentialFor($mine, ['name' => 'laptop']);
    $second = personalCredentialFor($mine, ['name' => 'phone']);
    $foreign = personalCredentialFor($theirs, ['name' => 'their-laptop']);

    $response = $this->actingAsVersioned($mine)->getJson('/bfc/me/credentials')->assertOk();

    expect($response->json('credentials.*.id'))->toBe([$first->id, $second->id])
        ->and($response->json('credentials.*.subject_ref'))
        ->toBe([personalSubjectRef($mine), personalSubjectRef($mine)]);

    // Not merely absent from the rendering — the foreign row's id and name
    // appear nowhere in the payload at all.
    expect($response->getContent())->not->toContain($foreign->id)
        ->and($response->getContent())->not->toContain('their-laptop');
});

// ------------------------------------------- AC2: the subject is server-derived

it('binds a mint to the session-derived subject and never to a crafted one', function (): void {
    $mine = personalUser('mine@example.test');
    $victim = personalUser('victim@example.test');

    $this->actingAsVersioned($mine)->postJson('/bfc/me/credentials', [
        'name' => 'ci',
        // Every lever an attacker has for "make this someone else's":
        'subject_type' => SubjectType::Operator->value,
        'subject_ref' => personalSubjectRef($victim),
        'user_id' => (string) $victim->getAuthIdentifier(),
    ])->assertCreated();

    $credential = Credential::query()->where('name', 'ci')->sole();

    expect($credential->subject_type)->toBe(SubjectType::UserPrincipal)
        ->and($credential->purpose)->toBe(CredentialPurpose::Consumption)
        ->and($credential->subject_ref)->toBe(personalSubjectRef($mine))
        ->and($credential->user_id)->toBe((string) $mine->getAuthIdentifier());

    // And the audit actor is the session user, by id (D8's bound_user).
    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->actor_type)->toBe(AuditActorType::BoundUser)
        ->and($event->actor_ref)->toBe((string) $mine->getAuthIdentifier());
});

it('ignores a crafted subject even when the surface is called directly, not over HTTP', function (): void {
    $mine = personalUser('mine@example.test');
    $victim = personalUser('victim@example.test');

    $this->actingAsVersioned($mine);

    $request = Request::create('/bfc/me/credentials', 'POST');
    $request->setUserResolver(fn (): User => $mine);

    // A front end that hands the surface a MintOptions carrying someone
    // else's user id: the binding is rebuilt server-side regardless.
    app(PersonalCredentialSurface::class)->mintMine($request, new MintOptions(
        name: 'direct',
        userId: (string) $victim->getAuthIdentifier(),
    ));

    $credential = Credential::query()->where('name', 'direct')->sole();

    expect($credential->subject_ref)->toBe(personalSubjectRef($mine))
        ->and($credential->user_id)->toBe((string) $mine->getAuthIdentifier());
});

it('cannot mint the reserved signing-root identity through the personal adapter', function (): void {
    $mine = personalUser('reserved-root@example.test');
    $this->actingAsVersioned($mine);

    app()->instance(CredentialDeclaration::class, new class implements CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return new Subject(SubjectType::Installation, CredentialPurpose::SIGNING_ROOT_SUBJECT_REF);
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }
    });

    $request = Request::create('/bfc/me/credentials', 'POST');
    $request->setUserResolver(fn (): User => $mine);
    $before = Credential::query()->count();

    expect(fn () => app(PersonalCredentialSurface::class)->mintMine($request, new MintOptions))
        ->toThrow(CredentialVerbRefused::class, 'reserved for its dedicated lifecycle');
    expect(Credential::query()->count())->toBe($before);
});

// ------------------------------------------------------- AC3: reveal once (D7)

it('reveals the minted plaintext exactly once and leaks it into no other channel', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAsVersioned($mine);

    $response = $this->assertNoSecretLeakageOfMinted(
        fn () => $this->postJson('/bfc/me/credentials', ['name' => 'ci'])->assertCreated(),
        fn ($response): string => (string) $response->json('delivery.secret'),
    );

    $secret = (string) $response->json('delivery.secret');

    expect($secret)->toStartWith('tok_');

    // The response IS the one delivery: exactly one occurrence, and
    // nothing beyond it (headers included) carries the marker.
    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $secret);

    foreach ($response->headers->all() as $values) {
        foreach ($values as $value) {
            expect((string) $value)->not->toContain($secret);
        }
    }

    // The store kept the hash, never the plaintext.
    expect(Credential::query()->where('name', 'ci')->sole()->secret_hash)->toBe(hash('sha256', $secret));

    // And the surface never hands it back a second time.
    $listing = $this->getJson('/bfc/me/credentials')->assertOk();

    $this->assertResponseCarriesNoSecret($listing, $secret);
});

// ----------------------------------------------------------- AC4 + AC5: denial

it('revokes a row the caller owns', function (): void {
    $mine = personalUser('mine@example.test');
    $credential = personalCredentialFor($mine);

    $this->actingAsVersioned($mine)->deleteJson('/bfc/me/credentials/'.$credential->id)->assertNoContent();

    expect($credential->refresh()->revoked_at)->not->toBeNull();

    // Idempotent, exactly like the operator verb.
    $this->actingAsVersioned($mine)->deleteJson('/bfc/me/credentials/'.$credential->id)->assertNoContent();

    expect(CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::Revoked)
        ->count())->toBe(1);
});

it('denies every cross-user path by any crafted input', function (): void {
    $attacker = personalUser('attacker@example.test');
    $victim = personalUser('victim@example.test');

    $victimCredential = personalCredentialFor($victim, ['name' => 'victims-key']);

    $this->actingAsVersioned($attacker);

    // 1 — cannot LIST the victim's rows, with or without a crafted subject.
    $listing = $this->getJson('/bfc/me/credentials?subject_ref='.urlencode(personalSubjectRef($victim)))
        ->assertOk();

    expect($listing->json('credentials'))->toBe([])
        ->and($listing->getContent())->not->toContain($victimCredential->id);

    // 2 — cannot MINT FOR the victim: the row binds to the attacker, so
    // the victim's own listing is unchanged.
    $this->postJson('/bfc/me/credentials', [
        'name' => 'planted',
        'subject_ref' => personalSubjectRef($victim),
        'user_id' => (string) $victim->getAuthIdentifier(),
    ])->assertCreated();

    $planted = Credential::query()->where('name', 'planted')->sole();

    expect($planted->subject_ref)->toBe(personalSubjectRef($attacker))
        ->and(Credential::query()
            ->where('subject_ref', personalSubjectRef($victim))
            ->pluck('id')
            ->all())->toBe([$victimCredential->id]);

    // 3 — cannot REVOKE the victim's row by id: 404, the same answer an id
    // that never existed gets, so existence is never disclosed. And the
    // victim's credential is untouched.
    $this->deleteJson('/bfc/me/credentials/'.$victimCredential->id)->assertNotFound();
    $this->deleteJson('/bfc/me/credentials/00000000-0000-0000-0000-000000000000')->assertNotFound();

    expect($victimCredential->refresh()->revoked_at)->toBeNull();

    // No death, so no revoked audit event was written for the victim.
    expect(CredentialAuditEvent::query()
        ->where('credential_id', $victimCredential->id)
        ->exists())->toBeFalse();
});

// --------------------------------------------------- AC6: declared unsupported

it('distinguishes declared-unsupported from null-but-supported and renders less when the declaration is thinner', function (): void {
    $mine = personalUser('mine@example.test');

    // A supported-but-empty field: `expires_at` is null because nothing
    // set one, not because the store cannot express it.
    personalCredentialFor($mine, ['name' => 'laptop', 'abilities' => [OperatorAbility::CredentialRead->value]]);

    $full = $this->actingAsVersioned($mine)->getJson('/bfc/me/credentials')->assertOk();

    expect($full->json('fields.supported'))->toBe(['name', 'abilities', 'last_used_at', 'expires_at'])
        ->and($full->json('fields.unsupported'))->toBe([])
        ->and($full->json('credentials.0.name'))->toBe('laptop')
        ->and($full->json('credentials.0.abilities'))->toBe([OperatorAbility::CredentialRead->value])
        ->and($full->json('credentials.0.expires_at'))->toBeNull()
        ->and($full->json('credentials.0.unsupported'))->toBe([]);

    // The SAME rows through a THINNER declaration: two fields become
    // unknowable rather than absent.
    SelfServiceDeclaration::$unsupported = ['abilities', 'expires_at'];

    $thin = $this->actingAsVersioned($mine)->getJson('/bfc/me/credentials')->assertOk();

    expect($thin->json('fields.supported'))->toBe(['name', 'last_used_at'])
        ->and($thin->json('fields.unsupported'))->toBe(['abilities', 'expires_at'])
        // Still rendered, because the declaration still expresses it.
        ->and($thin->json('credentials.0.name'))->toBe('laptop')
        // Null AND named: "unknowable here", not "absent".
        ->and($thin->json('credentials.0.abilities'))->toBeNull()
        ->and($thin->json('credentials.0.expires_at'))->toBeNull()
        ->and($thin->json('credentials.0.unsupported'))->toBe(['abilities', 'expires_at']);

    // The round trip: a mint that sets a declared-unsupported field is
    // refused, so the declaration is never made a lie by this surface.
    // `name` and not `abilities`, because abilities are no longer a
    // client-supplied field here at all (rework Fix 2) — they come from
    // the self-service policy, so there is nothing for a caller to set.
    SelfServiceDeclaration::$unsupported = ['name'];

    $this->actingAsVersioned($mine)->postJson('/bfc/me/credentials', [
        'name' => 'ci',
    ])->assertForbidden();

    expect(Credential::query()->where('name', 'ci')->exists())->toBeFalse();
});

// ------------------------------------------------------- AC7: no session, no surface

it('rejects the personal surface without a session', function (): void {
    $mine = personalUser('mine@example.test');
    $credential = personalCredentialFor($mine);

    $this->getJson('/bfc/me/credentials')->assertUnauthorized();
    $this->postJson('/bfc/me/credentials', ['name' => 'ci'])->assertUnauthorized();
    $this->deleteJson('/bfc/me/credentials/'.$credential->id)->assertUnauthorized();

    expect(Credential::query()->where('name', 'ci')->exists())->toBeFalse()
        ->and($credential->refresh()->revoked_at)->toBeNull();
});

it('does not accept an operator credential in place of a session on the personal surface', function (): void {
    $mine = personalUser('mine@example.test');

    // A perfectly good operator credential for the operator surface's own gate
    // buys nothing here: this surface's gate is the session.
    $this->withHeader('Authorization', 'Bearer '.auditOperatorCredential('personal-probe'))
        ->getJson('/bfc/me/credentials')
        ->assertUnauthorized();

    expect(Credential::query()->pluck('subject_ref')->all())->toBe(['personal-probe'])
        ->and(Credential::query()->count())->toBe(1);

    // Sanity: an operator credential does work on the operator listing, so
    // the rejection above is about this surface and not a broken credential.
    $this->withHeader('Authorization', 'Bearer '.auditOperatorCredential('personal-probe-2'))
        ->getJson('/bfc/credentials')
        ->assertOk();
});

// ----------------------------------------------- AC8: no resolvable subject

it('has nothing to act on when the declaration resolves no subject', function (): void {
    // The package's SHIPPED default declaration: resolveSubject returns
    // null, so an app that has not declared self-service gets a
    // fail-closed 403 rather than a listing that reads as "you hold none".
    config(['built-for-cloud.credentials.declaration' => null]);

    $mine = personalUser('mine@example.test');
    $credential = personalCredentialFor($mine);

    $this->actingAsVersioned($mine);

    $this->getJson('/bfc/me/credentials')
        ->assertForbidden()
        ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'declares no personal-credential subject'));

    $this->postJson('/bfc/me/credentials', ['name' => 'ci'])->assertForbidden();
    $this->deleteJson('/bfc/me/credentials/'.$credential->id)->assertForbidden();

    expect(Credential::query()->where('name', 'ci')->exists())->toBeFalse()
        ->and($credential->refresh()->revoked_at)->toBeNull();
});

it('drops a row from the personal listing when the declarations verb matrix denies list_metadata', function (): void {
    config(['built-for-cloud.credentials.declaration' => null]);

    $mine = personalUser('mine@example.test');
    personalCredentialFor($mine);

    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            $user = $request->user();

            return $user === null ? null : new Subject(SubjectType::UserPrincipal, 'user:'.$user->getAuthIdentifier());
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return $verb !== CredentialVerb::ListMetadata;
        }
    });

    $this->actingAsVersioned($mine)->getJson('/bfc/me/credentials')
        ->assertOk()
        ->assertJsonPath('credentials', []);
});

// ------------------------------------------- AC9: lifecycle rides the one store

it('stops authenticating a revoked personal credential and kills it when the bound user is offboarded', function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    Route::middleware('auth:bfc')->get('/personal-probe', fn (): array => ['ok' => true]);

    $mine = personalUser('mine@example.test');

    // The session guard is named on every acting-as below: Laravel's
    // `auth:bfc` middleware calls shouldUse('bfc') on a successful token
    // request, which would otherwise repoint the default guard for the
    // rest of THIS test process (one process, many requests — production
    // gets a fresh container per request and never sees it).
    $this->actingAsVersioned($mine, 'web');

    $secret = (string) $this->postJson('/bfc/me/credentials', ['name' => 'ci'])
        ->assertCreated()
        ->json('delivery.secret');

    $survivor = (string) $this->postJson('/bfc/me/credentials', ['name' => 'survivor'])
        ->assertCreated()
        ->json('delivery.secret');

    $credential = Credential::query()->where('name', 'ci')->sole();

    // Both authenticate while they live.
    $this->withHeader('Authorization', 'Bearer '.$secret)->getJson('/personal-probe')->assertOk();
    $this->withHeader('Authorization', 'Bearer '.$survivor)->getJson('/personal-probe')->assertOk();

    // Self-revoke through the personal surface kills the first one.
    $this->actingAsVersioned($mine, 'web')
        ->deleteJson('/bfc/me/credentials/'.$credential->id)
        ->assertNoContent();

    $this->withHeader('Authorization', 'Bearer '.$secret)->getJson('/personal-probe')->assertUnauthorized();
    $this->withHeader('Authorization', 'Bearer '.$survivor)->getJson('/personal-probe')->assertOk();

    // Offboarding the bound user (PRD 1.15) kills the survivor too — and
    // closes the personal screen to the session that outlived it.
    app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => SubjectType::UserPrincipal->value,
        'subject_ref' => personalSubjectRef($mine),
    ]));

    expect(Credential::query()->where('name', 'survivor')->sole()->revoked_at)->not->toBeNull();

    $this->withHeader('Authorization', 'Bearer '.$survivor)->getJson('/personal-probe')->assertUnauthorized();

    $this->actingAsVersioned($mine, 'web')->getJson('/bfc/me/credentials')->assertForbidden();
});

// ------------------------- REWORK FIX 2: the self-service mint fails CLOSED

it('mints no abilities at all when the app declares no self-service policy, so a low-privilege user cannot mint mcp:admin', function (): void {
    personalMcpRoutes();

    $mine = personalUser('mine@example.test');

    // The escalation attempt: a logged-in, otherwise powerless human asks
    // for the destructive MCP ability and the operator admin ability.
    $secret = (string) $this->actingAsVersioned($mine, 'web')
        ->postJson('/bfc/me/credentials', [
            'name' => 'ci',
            'abilities' => [OperatorAbility::McpAdmin->value, OperatorAbility::Admin->value],
        ])
        ->assertCreated()
        ->json('delivery.secret');

    // Not narrowed, not filtered — never read. The row holds NOTHING.
    $credential = Credential::query()->where('name', 'ci')->sole();

    expect($credential->abilities)->toBeNull()
        ->and($credential->hasAbility(OperatorAbility::McpAdmin->value))->toBeFalse()
        ->and($credential->hasAbility(OperatorAbility::Admin->value))->toBeFalse();

    // And the ability is not merely absent from a column: the credential
    // cannot invoke the destructive tool, or the read tool, or the
    // operator surface the admin ability would have opened.
    $header = ['Authorization' => 'Bearer '.$secret];

    $this->postJson('/mcp/purge', [], $header)->assertForbidden();
    $this->postJson('/mcp/status', [], $header)->assertForbidden();
    $this->getJson('/bfc/credentials', $header)->assertUnauthorized();
});

it('grants exactly the self-service policy abilities and never the clients', function (): void {
    personalMcpRoutes();

    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);

    // The app says: my users may mint themselves an MCP READ token.
    SelfServicePolicyDeclaration::$abilities = [OperatorAbility::McpRead->value];

    $mine = personalUser('mine@example.test');

    $secret = (string) $this->actingAsVersioned($mine, 'web')
        ->postJson('/bfc/me/credentials', [
            'name' => 'ci',
            // The client asks for more. It changes nothing.
            'abilities' => [OperatorAbility::McpAdmin->value],
        ])
        ->assertCreated()
        ->json('delivery.secret');

    expect(Credential::query()->where('name', 'ci')->sole()->abilities)
        ->toBe([OperatorAbility::McpRead->value]);

    $header = ['Authorization' => 'Bearer '.$secret];

    // Exactly the policy's grant: the read tool opens, the destructive
    // one does not.
    $this->postJson('/mcp/status', [], $header)->assertOk();
    $this->postJson('/mcp/purge', [], $header)->assertForbidden();
});

it('drops client abilities even when the surface is called directly, not over HTTP', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAsVersioned($mine, 'web');

    $request = Request::create('/bfc/me/credentials', 'POST');
    $request->setUserResolver(fn (): User => $mine);

    // A front end handing the surface a MintOptions carrying abilities:
    // the grant is rebuilt from the policy regardless, so the guarantee
    // is structural and not a request-whitelist rule.
    app(PersonalCredentialSurface::class)->mintMine($request, new MintOptions(
        name: 'direct',
        abilities: [OperatorAbility::McpAdmin->value],
    ));

    expect(Credential::query()->where('name', 'direct')->sole()->abilities)->toBeNull();
});

it('refuses a self-service credential kind the app has not opted in', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAsVersioned($mine, 'web');

    // `hmac` delivers signing key material and `asymmetric` an enrollment
    // code; neither is reachable by naming it. No policy means bearer only.
    foreach ([CredentialKind::Hmac, CredentialKind::Asymmetric, CredentialKind::Basic] as $kind) {
        $this->postJson('/bfc/me/credentials', ['name' => 'probe', 'kind' => $kind->value])
            ->assertForbidden()
            ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'does not offer'));
    }

    expect(Credential::query()->count())->toBe(0);

    // The default kind still works, and it is what an omitted kind means.
    $this->postJson('/bfc/me/credentials', ['name' => 'default-kind'])->assertCreated();

    expect(Credential::query()->where('name', 'default-kind')->sole()->kind)->toBe(CredentialKind::Bearer);
});

it('drives declaration-opted personal asymmetric enrollment as pending keyless and revocable', function (): void {
    $this->travelTo('2026-09-14T12:00:00+00:00');
    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);
    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Asymmetric];
    SelfServicePolicyDeclaration::$abilities = [OperatorAbility::McpRead->value];

    $mine = personalUser('asymmetric@example.test');
    $victim = personalUser('asymmetric-victim@example.test');

    $mint = $this->assertNoSecretLeakageOfMinted(
        fn () => $this->actingAsVersioned($mine, 'web')->postJson('/bfc/me/credentials', [
            'kind' => CredentialKind::Asymmetric->value,
            'name' => 'personal enrollment',
            'code_ttl_seconds' => 120,
            'purpose' => CredentialPurpose::Signing->value,
            'subject_type' => SubjectType::Operator->value,
            'subject_ref' => personalSubjectRef($victim),
            'user_id' => (string) $victim->getKey(),
            'abilities' => [OperatorAbility::Admin->value],
        ])->assertCreated(),
        fn (TestResponse $response): string => (string) $response->json('delivery.enrollment_code'),
    );

    $code = (string) $mint->json('delivery.enrollment_code');
    $credentialId = (string) $mint->json('credential.id');

    $mint->assertJsonPath('delivery.shape', 'enrollment_code')
        ->assertJsonPath('credential.kind', CredentialKind::Asymmetric->value)
        ->assertJsonPath('credential.purpose', CredentialPurpose::Enrollment->value)
        ->assertJsonPath('credential.subject_type', SubjectType::UserPrincipal->value)
        ->assertJsonPath('credential.subject_ref', personalSubjectRef($mine))
        ->assertJsonPath('credential.status', CredentialStatus::Pending->value);

    expect($code)->toMatch('/^[0-9a-f]{64}$/')
        ->and($mint->getContent())->not->toContain('private_key', 'public_key', 'signing_key');
    $this->assertRevealsSecretExactlyOnce((string) $mint->getContent(), $code);

    $credential = Credential::query()->findOrFail($credentialId);
    $stored = DB::table('credentials')->where('id', $credentialId)->sole();
    $codeRow = OnboardingToken::query()->where('durable_credential_id', $credentialId)->sole();

    expect($credential->kind)->toBe(CredentialKind::Asymmetric)
        ->and($credential->purpose)->toBe(CredentialPurpose::Enrollment)
        ->and($credential->subject_type)->toBe(SubjectType::UserPrincipal)
        ->and($credential->subject_ref)->toBe(personalSubjectRef($mine))
        ->and((string) $credential->user_id)->toBe((string) $mine->getKey())
        ->and($credential->abilities)->toBe([OperatorAbility::McpRead->value])
        ->and($credential->status)->toBe(CredentialStatus::Pending)
        ->and($stored->public_key)->toBeNull()
        ->and($stored->secret_hash)->toBeNull()
        ->and($stored->secret_ciphertext)->toBeNull()
        ->and(collect(Schema::getColumnListing('credentials'))->contains(
            static fn (string $column): bool => str_contains($column, 'private_key'),
        ))->toBeFalse()
        ->and($codeRow->token_hash)->toBe(OnboardingToken::hashToken($code))
        ->and($codeRow->consumed_at)->toBeNull()
        ->and($codeRow->expires_at->toAtomString())->toBe('2026-09-14T12:02:00+00:00')
        ->and(OnboardingToken::query()->pending()->where('durable_credential_id', $credentialId)->count())->toBe(1);

    $this->assertResponseCarriesNoSecret(
        $this->actingAsVersioned($mine, 'web')->getJson('/bfc/me/credentials')->assertOk(),
        $code,
    );

    $this->actingAsVersioned($mine, 'web')
        ->deleteJson('/bfc/me/credentials/'.$credentialId)
        ->assertNoContent();

    $consumedAt = $codeRow->refresh()->consumed_at?->toAtomString();

    expect($credential->refresh()->revoked_at)->not->toBeNull()
        ->and($consumedAt)->toBe('2026-09-14T12:00:00+00:00')
        ->and(OnboardingToken::resolve($code))->toBeNull();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');

    $this->actingAsVersioned($mine, 'web')
        ->deleteJson('/bfc/me/credentials/'.$credentialId)
        ->assertNoContent();

    expect($codeRow->refresh()->consumed_at?->toAtomString())->toBe($consumedAt)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $credentialId)
            ->where('event', LifecycleEventType::Revoked)
            ->count())->toBe(1);
});

it('refuses personal asymmetric enrollment by default before every effect', function (): void {
    $mine = personalUser('asymmetric-default-refusal@example.test');

    $response = $this->actingAsVersioned($mine, 'web')->postJson('/bfc/me/credentials', [
        'kind' => CredentialKind::Asymmetric->value,
        'name' => 'must not exist',
        'code_ttl_seconds' => 120,
    ])->assertForbidden()
        ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'does not offer'));

    expect($response->json('delivery'))->toBeNull()
        ->and(Credential::query()->count())->toBe(0)
        ->and(OnboardingToken::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
});

it('mints and uses an account-bound hmac key once the self-service policy opts it in', function (): void {
    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);

    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];

    $mine = personalUser('mine@example.test');
    $victim = personalUser('victim@example.test');

    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone);

    Route::post('/personal-hmac/{user}', function (Request $request): array {
        return ['credential_id' => $request->attributes->get('bfc.hmac_credential_id')];
    })->middleware('bfc.hmac');

    $mint = $this->assertNoSecretLeakageOfMinted(
        fn () => $this->actingAsVersioned($mine, 'web')->postJson('/bfc/me/credentials', [
            'name' => 'signing',
            'kind' => CredentialKind::Hmac->value,
            'subject_type' => SubjectType::Operator->value,
            'subject_ref' => personalSubjectRef($victim),
            'user_id' => (string) $victim->getKey(),
        ])->assertCreated(),
        fn ($response): string => (string) $response->json('delivery.signing_key'),
    );

    $keyId = (string) $mint->json('delivery.key_id');
    $signingKey = (string) $mint->json('delivery.signing_key');
    $fingerprint = (string) $mint->json('delivery.delivery_fingerprint');

    $mint->assertJsonPath('delivery.shape', 'signing_key')
        ->assertJsonPath('credential.id', $keyId)
        ->assertJsonPath('credential.subject_type', SubjectType::UserPrincipal->value)
        ->assertJsonPath('credential.subject_ref', personalSubjectRef($mine));

    expect($keyId)->not->toBe('')
        ->and($signingKey)->toMatch('/^[0-9a-f]{64}$/')
        ->and($fingerprint)->toMatch('/^[0-9a-f]{16}$/');

    $this->assertRevealsSecretExactlyOnce((string) $mint->getContent(), $signingKey);
    $this->assertResponseCarriesNoSecret(
        $this->actingAsVersioned($mine, 'web')->getJson('/bfc/me/credentials')->assertOk(),
        $signingKey,
    );

    $credential = Credential::query()->findOrFail($keyId);
    $stored = DB::table('credentials')->where('id', $keyId)->sole();

    expect($credential->kind)->toBe(CredentialKind::Hmac)
        ->and($credential->subject_type)->toBe(SubjectType::UserPrincipal)
        ->and($credential->subject_ref)->toBe(personalSubjectRef($mine))
        ->and((string) $credential->user_id)->toBe((string) $mine->getKey())
        ->and($credential->last_used_at)->toBeNull()
        ->and($stored->secret_hash)->toBeNull()
        ->and($stored->public_key)->toBeNull()
        ->and($stored->secret_key_version)->not->toBeNull()
        ->and($stored->secret_ciphertext)->not->toContain($signingKey)
        ->and($stored->secret_ciphertext)->not->toBe(hash('sha256', $signingKey))
        ->and(app(HmacKeyring::class)->decrypt($stored->secret_ciphertext, $stored->secret_key_version))
        ->toBe($signingKey);

    $this->postJson('/bfc/credentials/'.$keyId.'/activate', [
        'delivery_fingerprint' => $fingerprint,
    ], [
        'Authorization' => 'Bearer '.auditOperatorCredential(
            'self-service-hmac-activation',
            [OperatorAbility::CredentialRotate->value],
        ),
    ])->assertOk()
        ->assertJsonPath('credential.id', $keyId)
        ->assertJsonPath('credential.status', CredentialStatus::Active->value);

    $body = '{"event":"self-service"}';
    $envelope = new HmacEnvelope(
        keyId: $keyId,
        eventType: 'self-service.test',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: (string) config('built-for-cloud.hmac.audience'),
    );
    $header = $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $signingKey));

    $this->call('POST', '/personal-hmac/'.$mine->getKey(), server: [
        'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $header,
        'CONTENT_TYPE' => 'application/json',
    ], content: $body)
        ->assertOk()
        ->assertJsonPath('credential_id', $keyId);

    expect($credential->refresh()->last_used_at)->not->toBeNull();
});

it('uses the K5 minted hmac credential through grace reset and the exact managed 1799 1800 boundary', function (): void {
    $this->travelTo('2026-09-10T12:00:00+00:00');
    $user = personalUser('p5d-boundary@example.test');
    $delivery = p5dMintActivatedPersonalHmac($user);
    $fixture = p5dConfigureManagedPersonalUser($user);
    Route::post('/p5d-personal-hmac/{user}', static fn (): array => ['verified' => true])->middleware('bfc.hmac');
    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'server_error',
    ], 503);

    $this->travelTo('2026-09-10T12:05:00+00:00');
    p5dSendPersonalHmac($user, $delivery)->assertOk()->assertJsonPath('verified', true);
    expect($user->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00');

    $fixture->confirmationResponder = null;
    $this->travelTo('2026-09-10T12:10:00+00:00');
    p5dSendPersonalHmac($user, $delivery)->assertOk();
    expect($user->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:10:00+00:00');

    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'server_error',
    ], 503);
    $this->travelTo('2026-09-10T12:39:59+00:00');
    p5dSendPersonalHmac($user, $delivery)->assertOk();
    $lastUsedAt = Credential::query()->findOrFail($delivery['key_id'])->last_used_at?->toAtomString();

    $this->travelTo('2026-09-10T12:40:00+00:00');
    p5dSendPersonalHmac($user, $delivery)->assertUnauthorized();
    expect(Credential::query()->findOrFail($delivery['key_id'])->last_used_at?->toAtomString())->toBe($lastUsedAt);
});

it('rejects a stale-membership bad hmac without authority calls retry charge or freshness mutation', function (): void {
    $this->travelTo('2026-09-10T12:00:00+00:00');
    $user = personalUser('p5d-bad-signature@example.test');
    $delivery = p5dMintActivatedPersonalHmac($user);
    $fixture = p5dConfigureManagedPersonalUser($user);
    Route::post('/p5d-personal-hmac/{user}', static fn (): array => ['verified' => true])->middleware('bfc.hmac');
    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'server_error',
    ], 503);

    $userBefore = $user->fresh()->getAttributes();
    $authorityBefore = (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();
    $credentialBefore = Credential::query()->findOrFail($delivery['key_id'])->getAttributes();
    $refreshKey = hash('sha256', implode("\0", [
        'https://issuer.example.test',
        'connection-fixture',
        'p5d-personal-subject',
    ]));
    $attemptKey = 'bfc:managed-refresh-attempt:'.$refreshKey;

    $this->travelTo('2026-09-10T12:29:59+00:00');
    $badSignature = p5dSendPersonalHmac($user, [
        'key_id' => $delivery['key_id'],
        'signing_key' => bin2hex(random_bytes(32)),
    ])->assertUnauthorized();

    expect($fixture->calls)->toBe([])
        ->and(Cache::has($attemptKey))->toBeFalse()
        ->and($user->fresh()->getAttributes())->toBe($userBefore)
        ->and((array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first())->toBe($authorityBefore)
        ->and(Credential::query()->findOrFail($delivery['key_id'])->getAttributes())->toBe($credentialBefore);

    $unusableKey = p5dSendPersonalHmac($user, [
        'key_id' => (string) Str::uuid(),
        'signing_key' => bin2hex(random_bytes(32)),
    ])->assertUnauthorized();

    expect($badSignature->getContent())->toBe($unusableKey->getContent());
});

it('denies and revokes the K5 minted hmac credential on authoritative removal', function (): void {
    $this->travelTo('2026-09-10T12:00:00+00:00');
    $user = personalUser('p5d-removal@example.test');
    $delivery = p5dMintActivatedPersonalHmac($user);
    $fixture = p5dConfigureManagedPersonalUser($user);
    Route::post('/p5d-personal-hmac/{user}', static fn (): array => ['verified' => true])->middleware('bfc.hmac');
    $fixture->confirmationOverrides = ['membership_status' => 'removed'];

    $this->travelTo('2026-09-10T12:05:00+00:00');
    p5dSendPersonalHmac($user, $delivery)->assertUnauthorized();

    expect(Credential::query()->findOrFail($delivery['key_id'])->revoked_at)->not->toBeNull();
});

it('persists personal hmac mint activation and middleware verification across fresh standalone processes', function (): void {
    $database = tempnam(sys_get_temp_dir(), 'bfc-p5b-personal-hmac-');
    expect($database)->toBeString();

    try {
        $setup = runPersonalHmacProcess('setup', $database);
        $mint = runPersonalHmacProcess('mint', $database);
        $delivery = $mint['body']['delivery'];

        expect($setup['authority'])->toBe(AuthorityMode::Standalone->value)
            ->and($mint['login_status'])->toBe(302)
            ->and($mint['status'])->toBe(201)
            ->and($delivery['shape'])->toBe('signing_key');

        $activation = runPersonalHmacProcess('activate', $database, [
            'key_id' => $delivery['key_id'],
            'delivery_fingerprint' => $delivery['delivery_fingerprint'],
            'admin_token' => $setup['admin_token'],
        ]);
        $verified = runPersonalHmacProcess('verify', $database, [
            'key_id' => $delivery['key_id'],
            'signing_key' => $delivery['signing_key'],
            'user_id' => $setup['user_id'],
        ]);
        $inspection = runPersonalHmacProcess('inspect', $database, [
            'key_id' => $delivery['key_id'],
            'signing_key' => $delivery['signing_key'],
        ]);

        expect($activation['status'])->toBe(200)
            ->and($verified['status'])->toBe(200)
            ->and($verified['body']['credential_id'])->toBe($delivery['key_id'])
            ->and($inspection['kind'])->toBe(CredentialKind::Hmac->value)
            ->and($inspection['status'])->toBe(CredentialStatus::Active->value)
            ->and($inspection['subject_ref'])->toBe('user:'.$setup['user_id'])
            ->and((string) $inspection['user_id'])->toBe((string) $setup['user_id'])
            ->and($inspection['ciphertext_contains_key'])->toBeFalse()
            ->and($inspection['decrypts_to_delivered_key'])->toBeTrue()
            ->and($inspection['last_used_at'])->not->toBeNull();
    } finally {
        if (is_string($database) && is_file($database)) {
            unlink($database);
        }
    }
});

/**
 * @param  array<string, mixed>  $value
 * @return array<string, mixed>
 */
function runPersonalHmacProcess(string $phase, string $database, array $value = []): array
{
    $process = new Process([
        PHP_BINARY,
        __DIR__.'/Fixtures/personal-hmac-process.php',
        $phase,
        $database,
        json_encode($value, JSON_THROW_ON_ERROR),
    ]);
    $process->run();

    expect($process->isSuccessful())->toBeTrue($process->getOutput().$process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

it('leaves the durable expiry caller-chosen and never defaults one on the self-service mint', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAsVersioned($mine, 'web');

    // Abilities fail closed; LIFETIME does not — a durable's expiry stays
    // the caller's choice with no default (PRD 1.3 / D1b: TTL defaults on
    // durables are a DO-NOT-BUILD). Omitted means no expiry.
    $this->postJson('/bfc/me/credentials', ['name' => 'no-expiry'])->assertCreated();

    expect(Credential::query()->where('name', 'no-expiry')->sole()->expires_at)->toBeNull();

    $chosen = now()->addDays(30)->startOfSecond();

    $this->postJson('/bfc/me/credentials', [
        'name' => 'chosen-expiry',
        'expires_at' => $chosen->toIso8601String(),
    ])->assertCreated();

    expect(Credential::query()->where('name', 'chosen-expiry')->sole()->expires_at->toIso8601String())
        ->toBe($chosen->toIso8601String());
});

// ------------- REWORK FIX 1: browser session routes, CSRF on the mutations

it('rejects a mutating personal request that carries no valid CSRF token', function (): void {
    $mine = personalUser('mine@example.test');
    $credential = personalCredentialFor($mine);

    $this->actingAsVersioned($mine, 'web');

    // PreventRequestForgery short-circuits while the app reports itself as
    // running unit tests, which is exactly why every other test here can
    // post without a token. Flip that off to exercise the real gate.
    app()->instance('env', 'local');

    $this->post('/bfc/me/credentials', ['name' => 'forged'])->assertStatus(419);
    $this->delete('/bfc/me/credentials/'.$credential->id)->assertStatus(419);

    expect(Credential::query()->where('name', 'forged')->exists())->toBeFalse()
        ->and($credential->refresh()->revoked_at)->toBeNull();

    // The read verb is not CSRF-checked (PreventRequestForgery exempts
    // read verbs itself) — it is how a front end picks up its token.
    $this->get('/bfc/me/credentials')->assertOk();

    // And with a matching token the same mutations go through.
    $token = 'personal-csrf-'.bin2hex(random_bytes(8));

    $this->withSession(['_token' => $token])
        ->post('/bfc/me/credentials', ['name' => 'legitimate', '_token' => $token])
        ->assertCreated();

    $this->withSession(['_token' => $token])
        ->delete('/bfc/me/credentials/'.$credential->id, ['_token' => $token])
        ->assertNoContent();

    expect(Credential::query()->where('name', 'legitimate')->exists())->toBeTrue()
        ->and($credential->refresh()->revoked_at)->not->toBeNull();
});

// --------------------------------------------------------- AC10: wiring parity

it('mounts the personal routes on the routes surface family, at fixed paths, behind the session gate', function (): void {
    $personal = collect(Route::getRoutes()->getRoutes())
        ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/credentials'))
        ->values();

    expect($personal->map(fn (RoutingRoute $route): string => $route->methods()[0].' /'.$route->uri())->all())
        ->toBe([
            'GET /bfc/me/credentials',
            'POST /bfc/me/credentials',
            'DELETE /bfc/me/credentials/{id}',
        ]);

    foreach ($personal as $route) {
        $declared = $route->gatherMiddleware();

        // The RESOLVED stack: middleware groups expanded to real classes,
        // so the assertion holds whether the surface rode the host's `web`
        // group or the package's own fallback stack.
        $resolved = app('router')->gatherRouteMiddleware($route);

        expect($declared)->toContain(EnsureUserIsAuthenticated::class)
            ->and($declared)->toContain('throttle:bfc-personal')
            // No operator gate, ever: this surface is the session's.
            ->and(collect($declared)->filter(fn (mixed $one): bool => is_string($one) && (
                str_starts_with($one, EnsureCredentialAdmin::class)
                || str_starts_with($one, 'bfc.credential.admin')
            ))->all())
            ->toBe([])
            // Rework Fix 1: these are BROWSER routes. Without StartSession
            // a cookie session never starts (every request 401s), and
            // without the CSRF middleware a session-riding forgery could
            // mint or revoke on a logged-in user's behalf.
            ->and($resolved)->toContain(StartSession::class)
            ->and($resolved)->toContain(PreventRequestForgery::class);
    }
});
