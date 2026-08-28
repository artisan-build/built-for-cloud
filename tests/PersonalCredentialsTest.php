<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

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
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => personalSubjectRef($user),
        'user_id' => (string) $user->getAuthIdentifier(),
        'name' => 'laptop',
        'status' => CredentialStatus::Active,
        'secret_hash' => hash('sha256', 'seeded-'.bin2hex(random_bytes(8))),
    ], $attributes));
}

// ------------------------------------------------------------ AC1: list mine

it('lists only the authenticated users own credentials', function (): void {
    $mine = personalUser('mine@example.test');
    $theirs = personalUser('theirs@example.test');

    $first = personalCredentialFor($mine, ['name' => 'laptop']);
    $second = personalCredentialFor($mine, ['name' => 'phone']);
    $foreign = personalCredentialFor($theirs, ['name' => 'their-laptop']);

    $response = $this->actingAs($mine)->getJson('/bfc/me/credentials')->assertOk();

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

    $this->actingAs($mine)->postJson('/bfc/me/credentials', [
        'name' => 'ci',
        // Every lever an attacker has for "make this someone else's":
        'subject_type' => SubjectType::Operator->value,
        'subject_ref' => personalSubjectRef($victim),
        'user_id' => (string) $victim->getAuthIdentifier(),
    ])->assertCreated();

    $credential = Credential::query()->where('name', 'ci')->sole();

    expect($credential->subject_type)->toBe(SubjectType::UserPrincipal)
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

    $this->actingAs($mine);

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

// ------------------------------------------------------- AC3: reveal once (D7)

it('reveals the minted plaintext exactly once and leaks it into no other channel', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAs($mine);

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

    $this->actingAs($mine)->deleteJson('/bfc/me/credentials/'.$credential->id)->assertNoContent();

    expect($credential->refresh()->revoked_at)->not->toBeNull();

    // Idempotent, exactly like the operator verb.
    $this->actingAs($mine)->deleteJson('/bfc/me/credentials/'.$credential->id)->assertNoContent();

    expect(CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::Revoked)
        ->count())->toBe(1);
});

it('denies every cross-user path by any crafted input', function (): void {
    $attacker = personalUser('attacker@example.test');
    $victim = personalUser('victim@example.test');

    $victimCredential = personalCredentialFor($victim, ['name' => 'victims-key']);

    $this->actingAs($attacker);

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
    personalCredentialFor($mine, ['name' => 'laptop', 'abilities' => ['consume']]);

    $full = $this->actingAs($mine)->getJson('/bfc/me/credentials')->assertOk();

    expect($full->json('fields.supported'))->toBe(['name', 'abilities', 'last_used_at', 'expires_at'])
        ->and($full->json('fields.unsupported'))->toBe([])
        ->and($full->json('credentials.0.name'))->toBe('laptop')
        ->and($full->json('credentials.0.abilities'))->toBe(['consume'])
        ->and($full->json('credentials.0.expires_at'))->toBeNull()
        ->and($full->json('credentials.0.unsupported'))->toBe([]);

    // The SAME rows through a THINNER declaration: two fields become
    // unknowable rather than absent.
    SelfServiceDeclaration::$unsupported = ['abilities', 'expires_at'];

    $thin = $this->actingAs($mine)->getJson('/bfc/me/credentials')->assertOk();

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

    $this->actingAs($mine)->postJson('/bfc/me/credentials', [
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

    // A perfectly good admin token — the operator surface's own gate —
    // buys nothing here: this surface's gate is the session.
    $this->withHeader('Authorization', 'Bearer '.auditAdminToken('personal-probe'))
        ->getJson('/bfc/me/credentials')
        ->assertUnauthorized();

    expect(Credential::query()->count())->toBe(0);

    // Sanity: the same token DOES work on the operator listing, so the
    // rejection above is about this surface and not a broken token.
    $this->withHeader('Authorization', 'Bearer '.auditAdminToken('personal-probe-2'))
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

    $this->actingAs($mine);

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

    $this->actingAs($mine)->getJson('/bfc/me/credentials')
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
    $this->actingAs($mine, 'web');

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
    $this->actingAs($mine, 'web')
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

    $this->actingAs($mine, 'web')->getJson('/bfc/me/credentials')->assertForbidden();
});

// ------------------------- REWORK FIX 2: the self-service mint fails CLOSED

it('mints no abilities at all when the app declares no self-service policy, so a low-privilege user cannot mint mcp:admin', function (): void {
    personalMcpRoutes();

    $mine = personalUser('mine@example.test');

    // The escalation attempt: a logged-in, otherwise powerless human asks
    // for the destructive MCP ability and the operator admin ability.
    $secret = (string) $this->actingAs($mine, 'web')
        ->postJson('/bfc/me/credentials', [
            'name' => 'ci',
            'abilities' => [OperatorAbility::McpAdmin->value, OperatorAbility::ADMIN],
        ])
        ->assertCreated()
        ->json('delivery.secret');

    // Not narrowed, not filtered — never read. The row holds NOTHING.
    $credential = Credential::query()->where('name', 'ci')->sole();

    expect($credential->abilities)->toBeNull()
        ->and($credential->hasAbility(OperatorAbility::McpAdmin->value))->toBeFalse()
        ->and($credential->hasAbility(OperatorAbility::ADMIN))->toBeFalse();

    // And the ability is not merely absent from a column: the credential
    // cannot invoke the destructive tool, or the read tool, or the
    // operator surface the admin ability would have opened.
    $header = ['Authorization' => 'Bearer '.$secret];

    $this->postJson('/mcp/purge', [], $header)->assertForbidden();
    $this->postJson('/mcp/status', [], $header)->assertForbidden();
    $this->getJson('/bfc/credentials', $header)->assertForbidden();
});

it('grants exactly the self-service policy abilities and never the clients', function (): void {
    personalMcpRoutes();

    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);

    // The app says: my users may mint themselves an MCP READ token.
    SelfServicePolicyDeclaration::$abilities = [OperatorAbility::McpRead->value];

    $mine = personalUser('mine@example.test');

    $secret = (string) $this->actingAs($mine, 'web')
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

    $this->actingAs($mine, 'web');

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

    $this->actingAs($mine, 'web');

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

it('offers a kind once the self-service policy opts it in', function (): void {
    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);

    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];

    $mine = personalUser('mine@example.test');

    $this->actingAs($mine, 'web')
        ->postJson('/bfc/me/credentials', ['name' => 'signing', 'kind' => CredentialKind::Hmac->value])
        ->assertCreated()
        ->assertJsonPath('delivery.shape', 'signing_key');

    expect(Credential::query()->where('name', 'signing')->sole()->kind)->toBe(CredentialKind::Hmac);
});

it('leaves the durable expiry caller-chosen and never defaults one on the self-service mint', function (): void {
    $mine = personalUser('mine@example.test');

    $this->actingAs($mine, 'web');

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

    $this->actingAs($mine, 'web');

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
        ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/'))
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

        expect($declared)->toContain('bfc.auth')
            ->and($declared)->toContain('throttle:bfc-personal')
            // No operator gate, ever: this surface is the session's.
            ->and(collect($declared)->filter(fn (mixed $one): bool => is_string($one) && str_starts_with($one, 'bfc.credential.admin'))->all())
            ->toBe([])
            // Rework Fix 1: these are BROWSER routes. Without StartSession
            // a cookie session never starts (every request 401s), and
            // without the CSRF middleware a session-riding forgery could
            // mint or revoke on a logged-in user's behalf.
            ->and($resolved)->toContain(StartSession::class)
            ->and($resolved)->toContain(PreventRequestForgery::class);
    }
});
