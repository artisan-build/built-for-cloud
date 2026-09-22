<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);

    Route::post('/mcp-probe', function (Request $request): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();
        $actorCredentialId = $request->attributes->get('bfc.actor_credential_id');
        $audit = is_string($actorCredentialId) && $actorCredentialId !== ''
            ? AuditActor::operatorIntegration($actorCredentialId)
            : ($acting->check() ? AppActionActor::fromActingPrincipal($acting) : null);
        $user = $request->user();
        $userId = match (true) {
            $user instanceof DelegatedActor => $user->getAuthIdentifier(),
            $user instanceof Credential => $user->getKey(),
            default => null,
        };

        return [
            'user_type' => is_object($user) ? $user::class : null,
            'user_id' => $userId,
            'actor_token_id' => $request->attributes->get('bfc.actor_token_id'),
            'actor_credential_id' => $actorCredentialId,
            'acting_id' => $acting->identifier(),
            'delegated' => $acting->delegated,
            'guard' => $acting->guard,
            'role' => $acting->role?->value,
            'on_behalf_of' => $acting->onBehalfOf,
            'audit_type' => $audit?->type->value,
            'audit_ref' => $audit?->ref,
            'audit_agency' => $audit instanceof AppActionActor ? $audit->onBehalfOf : null,
            'authorization' => $request->header('Authorization'),
            'server_authorization' => $request->server->get('HTTP_AUTHORIZATION'),
            'redirect_server_authorization' => $request->server->get('REDIRECT_HTTP_AUTHORIZATION'),
            'system_authority' => app(SystemAuthorityContext::class)->active(),
        ];
    })->middleware('bfc.mcp');

    Route::middleware([StartSession::class, 'bfc.mcp'])
        ->post('/mcp-session-probe', fn (Request $request): array => $request->session()->all());

    Route::middleware([StartSession::class, 'bfc.mcp'])
        ->post('/mcp-precedence-probe', function (): array {
            $acting = app(ActingPrincipalResolver::class)->resolve();

            return [
                'refused' => $acting->wasRefused(),
                'principal' => $acting->identifier(),
                'delegated' => $acting->delegated,
                'delegated_session_present' => $acting->delegatedSessionPresent(),
            ];
        });

    Route::post('/mcp-admin-probe', fn (): array => ['admitted' => true])
        ->middleware(['bfc.mcp', 'bfc.admin']);

    Route::post('/mcp-local-auth-probe', fn (): array => ['admitted' => true])
        ->middleware(['bfc.mcp', 'bfc.auth']);

    Route::post('/mcp-personal-probe', function (Request $request): array {
        try {
            app(PersonalCredentialSurface::class)->mine($request);
        } catch (SelfServiceUnavailable) {
            return ['refused' => true];
        }

        return ['refused' => false];
    })->middleware('bfc.mcp');

    // A downstream MCP tool that verifies or relays an assertion of its
    // own, exactly what hone and the scalpels relay do.
    Route::post('/mcp-downstream-refusal', function (): never {
        throw AssertionRefused::because(AssertionRefusalReason::SignatureInvalid);
    })->middleware('bfc.mcp');
});

/**
 * @param  array<string, mixed>  $overrides
 */
function mcpAssertion(array $overrides = [], string $keyId = 'k1', ?AsymmetricSecretKey $secret = null): string
{
    $secret ??= consoleTestSigningKey();

    return consoleMint($secret, consoleClaims(array_merge(['purpose' => 'mcp'], $overrides)), $keyId);
}

/**
 * @param  array<string, mixed>  $overrides
 */
function mcpRequest(array $overrides = [], string $keyId = 'k1', ?AsymmetricSecretKey $secret = null): TestResponse
{
    return test()->postJson('/mcp-probe', [], [
        'Authorization' => 'Bearer '.mcpAssertion($overrides, $keyId, $secret),
    ]);
}

/** @param list<string>|null $abilities */
function mcpStoreCredential(
    string $secret,
    SubjectType $subjectType = SubjectType::ExternalConsumer,
    ?array $abilities = null,
    CredentialPurpose $purpose = CredentialPurpose::Mcp,
): Credential {
    return Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => $purpose,
        'subject_type' => $subjectType,
        'subject_ref' => 'mcp-'.bin2hex(random_bytes(8)),
        'name' => 'mcp credential',
        'abilities' => $abilities,
        'secret_hash' => hash('sha256', $secret),
    ]);
}

/**
 * @return list<string>
 */
function mcpRefusalReasons(): array
{
    $reasons = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('note', 'like', AuthenticateMcp::AUDIT_NOTE.'%')
        ->pluck('note')
        ->map(static fn (mixed $note): string => str_replace(AuthenticateMcp::AUDIT_NOTE, '', (string) $note))
        ->all();

    sort($reasons);

    return $reasons;
}

it('publishes the assertion actor and this handoff claims on the request', function (): void {
    $response = mcpRequest([
        'sub' => 'mcp-operator',
        'display_name' => 'MCP Operator',
        'role' => 'member',
        'on_behalf_of' => 'Acme Agency',
    ])->assertOk();

    $actor = DelegatedActor::query()->sole();

    $response
        ->assertJsonPath('user_type', DelegatedActor::class)
        ->assertJsonPath('user_id', $actor->getAuthIdentifier())
        ->assertJsonPath('acting_id', $actor->getAuthIdentifier())
        ->assertJsonPath('delegated', true)
        ->assertJsonPath('guard', null)
        ->assertJsonPath('role', 'member')
        ->assertJsonPath('on_behalf_of', 'Acme Agency')
        ->assertJsonPath('audit_type', AppActorType::DelegatedActor->value)
        ->assertJsonPath('audit_ref', $actor->getAuthIdentifier())
        ->assertJsonPath('audit_agency', 'Acme Agency')
        ->assertJsonPath('authorization', null)
        ->assertJsonPath('system_authority', false);

    expect(AssertionBurn::query()->count())->toBe(1);
});

it('takes the bearer out of the server bag as well as the headers', function (): void {
    // Rich exception reporters serialize `$request->server` alongside
    // the trace, so clearing the header alone leaves the live
    // credential in the object a reporter would capture. Apache's
    // rewrite copy rides the same request here to prove the set the
    // middleware clears is the set the carrier arrives in.
    $assertion = mcpAssertion();

    $this->call('POST', '/mcp-probe', [], [], [], [
        'HTTP_AUTHORIZATION' => 'Bearer '.$assertion,
        'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer '.$assertion,
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
    ])->assertOk()
        ->assertJsonPath('authorization', null)
        ->assertJsonPath('server_authorization', null)
        ->assertJsonPath('redirect_server_authorization', null);
});

it('refuses a replay because its mint is spent and audits the bounded reason', function (): void {
    $assertion = mcpAssertion();
    $headers = ['Authorization' => 'Bearer '.$assertion];

    $this->postJson('/mcp-probe', [], $headers)->assertOk();
    $refused = $this->postJson('/mcp-probe', [], $headers)->assertUnauthorized();

    expect(AssertionBurn::query()->count())->toBe(1)
        ->and(mcpRefusalReasons())->toBe([ConsoleEntryRefusalReason::Replayed->value]);

    $refused->assertExactJson(['message' => 'Unauthenticated.']);
});

it('uniformly refuses audience ttl purpose key and signature failures while auditing each reason', function (): void {
    $now = CarbonImmutable::now();
    $foreign = consoleKeypair();

    $responses = [
        mcpRequest(['aud' => 'https://another-deployment.test']),
        mcpRequest([
            'iat' => $now->toAtomString(),
            'nbf' => $now->toAtomString(),
            'exp' => $now->addSeconds(121)->toAtomString(),
        ]),
        mcpRequest(['purpose' => 'console-entry']),
        mcpRequest(['purpose' => consoleAbsent()]),
        mcpRequest([], 'foreign-kid', $foreign),
        mcpRequest([], 'k1', consoleKeypair()),
    ];

    foreach ($responses as $response) {
        $response->assertUnauthorized()->assertExactJson(['message' => 'Unauthenticated.']);
        expect($response->getContent())->toBe($responses[0]->getContent());
    }

    expect(mcpRefusalReasons())->toBe([
        AssertionRefusalReason::AudienceMismatch->value,
        ConsoleEntryRefusalReason::PurposeMismatch->value,
        ConsoleEntryRefusalReason::PurposeMismatch->value,
        AssertionRefusalReason::SignatureInvalid->value,
        AssertionRefusalReason::TtlTooLong->value,
        AssertionRefusalReason::UnknownKey->value,
    ]);
});

it('honours current and previous active keys during rotation overlap', function (): void {
    $previous = consoleKeypair();
    $current = consoleKeypair();

    consoleFileKey('previous', $previous);
    consoleFileKey('current', $current);

    mcpRequest([], 'previous', $previous)->assertOk();
    mcpRequest([], 'current', $current)->assertOk();

    expect(DelegatedActor::query()->count())->toBe(1)
        ->and(AssertionBurn::query()->count())->toBe(2);
});

it('keeps the contained actor handoff but rolls back its burn and principal', function (): void {
    mcpRequest(['sub' => 'contained'])->assertOk();

    $actor = DelegatedActor::query()->sole();
    $actor->deactivate();

    mcpRequest(['sub' => 'contained', 'display_name' => 'Contained Renamed'])
        ->assertUnauthorized();

    expect($actor->refresh()->last_handoff_display_name)->toBe('Contained Renamed')
        ->and(AssertionBurn::query()->count())->toBe(1)
        ->and(mcpRefusalReasons())->toBe([ConsoleEntryRefusalReason::ActorDeactivated->value]);
});

it('writes no session key under an assertion', function (): void {
    // Stateless by construction: the delegated principal lives on the
    // request object and nowhere else, so the session that entered this
    // request is EXACTLY the session that leaves it — no key added, not
    // only none of a known set.
    $session = $this->withSession(['sentinel' => 'kept'])
        ->postJson('/mcp-session-probe', [], ['Authorization' => 'Bearer '.mcpAssertion()])
        ->assertOk()
        ->json();

    expect($session)->toHaveKey('sentinel', 'kept')
        // The framework's own CSRF token is the one key a session-
        // starting request legitimately gains; nothing else — and no
        // delegated principal or claim — may appear.
        ->and(array_values(array_diff(array_keys($session), ['_token'])))->toBe(['sentinel']);
});

it('authenticates a unified bearer, records its use and does not leak the prior request assertion memo', function (): void {
    mcpRequest(['sub' => 'first-request'])->assertOk();

    $plaintext = 'credential-'.bin2hex(random_bytes(16));
    $credential = mcpStoreCredential(
        $plaintext,
        SubjectType::Installation,
        [OperatorAbility::McpRead->value],
    );

    expect($credential->last_used_at)->toBeNull();

    $this->postJson('/mcp-probe', [], [
        'Authorization' => 'Bearer '.$plaintext,
        'X-BfC-Client-Id' => 'mcp-client',
    ])
        ->assertOk()
        ->assertJsonPath('user_type', Credential::class)
        ->assertJsonPath('user_id', $credential->getKey())
        ->assertJsonPath('actor_token_id', null)
        ->assertJsonPath('actor_credential_id', null)
        ->assertJsonPath('acting_id', null)
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('system_authority', true);

    $credential->refresh();

    expect($credential->last_used_at)->not->toBeNull()
        ->and($credential->client_identity)->toBe('mcp-client')
        ->and($credential->client_identity_last_seen_at)->not->toBeNull();
});

it('uniformly refuses a credential that dies between resolution and usage', function (): void {
    $plaintext = 'dies-before-use-'.bin2hex(random_bytes(16));
    $credential = mcpStoreCredential($plaintext);

    Credential::retrieved(static function (Credential $resolved) use ($credential): void {
        if ($resolved->id === $credential->id) {
            Credential::query()->whereKey($resolved->id)->delete();
        }
    });

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$plaintext])
        ->assertUnauthorized()
        ->assertExactJson(['message' => 'Unauthenticated.']);

    expect(CredentialAuditEvent::query()->where('credential_id', $credential->id)->count())->toBe(0);
});

it('refuses wrong-purpose unknown and revoked store bearers before usage identity actor or dispatch', function (): void {
    $wrongSecret = 'wrong-purpose-'.bin2hex(random_bytes(16));
    $wrong = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'wrong-protocol',
        'name' => 'wrong protocol',
        'abilities' => [OperatorAbility::McpRead->value, OperatorAbility::Admin->value],
        'secret_hash' => hash('sha256', $wrongSecret),
    ]);
    $revokedSecret = 'revoked-mcp-'.bin2hex(random_bytes(16));
    $revoked = mcpStoreCredential(
        $revokedSecret,
        SubjectType::Installation,
        [OperatorAbility::McpRead->value],
    );
    $revoked->forceFill(['revoked_at' => now()])->save();

    $dispatched = 0;
    $wrongRequest = Request::create('/mcp-probe', 'POST', server: [
        'HTTP_AUTHORIZATION' => 'Bearer '.$wrongSecret,
        'HTTP_X_BFC_CLIENT_ID' => 'wrong-purpose-client',
    ]);
    $wrongResponse = app(AuthenticateMcp::class)->handle(
        $wrongRequest,
        function () use (&$dispatched): SymfonyResponse {
            $dispatched++;

            return response('dispatched');
        },
    );
    expect($wrongResponse->getStatusCode())->toBe(401);
    $unknownResponse = $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer unknown'])->assertUnauthorized();
    $revokedResponse = $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$revokedSecret])->assertUnauthorized();

    expect($wrongResponse->getContent())->toBe($unknownResponse->getContent())
        ->and($revokedResponse->getContent())->toBe($unknownResponse->getContent())
        ->and($wrong->refresh()->last_used_at)->toBeNull()
        ->and($wrong->client_identity)->toBeNull()
        ->and($wrong->client_identity_last_seen_at)->toBeNull()
        ->and($wrongRequest->attributes->get('bfc.actor_credential_id'))->toBeNull()
        ->and($wrongRequest->user())->toBeNull()
        ->and($dispatched)->toBe(0)
        ->and(CredentialAuditEvent::query()->where('credential_id', $wrong->id)->count())->toBe(0);
});

it('keeps local and browser-session consumers closed to a request assertion', function (): void {
    foreach (['/mcp-admin-probe', '/mcp-local-auth-probe'] as $uri) {
        $this->postJson($uri, [], ['Authorization' => 'Bearer '.mcpAssertion()])
            ->assertForbidden();
    }

    $this->postJson('/mcp-personal-probe', [], ['Authorization' => 'Bearer '.mcpAssertion()])
        ->assertOk()
        ->assertJsonPath('refused', true);
});

it('gives a non-admin unified bearer no admin attribution', function (): void {
    $plaintext = 'non-admin-'.bin2hex(random_bytes(16));
    $credential = mcpStoreCredential($plaintext, SubjectType::ExternalConsumer, [OperatorAbility::McpRead->value]);

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$plaintext])
        ->assertOk()
        ->assertJsonPath('user_type', Credential::class)
        ->assertJsonPath('user_id', $credential->id)
        ->assertJsonPath('actor_token_id', null)
        ->assertJsonPath('actor_credential_id', null)
        ->assertJsonPath('audit_type', null)
        ->assertJsonPath('audit_ref', null);

    expect(CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::FirstUsed->value)
        ->count())->toBe(1);
});

it('attributes only an operator credential with credential admin ability', function (): void {
    $plaintext = 'operator-admin-'.bin2hex(random_bytes(16));
    $credential = mcpStoreCredential(
        $plaintext,
        SubjectType::Operator,
        [OperatorAbility::Admin->value],
        CredentialPurpose::OperatorManagement,
    );

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$plaintext])
        ->assertOk()
        ->assertJsonPath('user_type', Credential::class)
        ->assertJsonPath('user_id', $credential->id)
        ->assertJsonPath('actor_token_id', null)
        ->assertJsonPath('actor_credential_id', $credential->id)
        ->assertJsonPath('audit_type', AuditActorType::OperatorIntegration->value)
        ->assertJsonPath('audit_ref', $credential->id);

    expect(CredentialAuditEvent::query()->where('actor_type', AuditActorType::OperatorIntegration->value)->count())->toBe(0);
});

it('gives a non-operator with credential admin ability no admin attribution', function (): void {
    $plaintext = 'application-admin-'.bin2hex(random_bytes(16));
    $credential = mcpStoreCredential($plaintext, SubjectType::ExternalConsumer, [OperatorAbility::Admin->value]);

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$plaintext])
        ->assertOk()
        ->assertJsonPath('user_type', Credential::class)
        ->assertJsonPath('user_id', $credential->id)
        ->assertJsonPath('actor_token_id', null)
        ->assertJsonPath('actor_credential_id', null)
        ->assertJsonPath('audit_type', null)
        ->assertJsonPath('audit_ref', null);

    expect(CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::FirstUsed->value)
        ->count())->toBe(1);
});

it('never falls through between store bearer and assertion authentication paths', function (): void {
    // An ordinary invalid bearer is never parsed or assertion-audited.
    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer not-an-assertion'])
        ->assertUnauthorized();

    $foreign = consoleKeypair();
    $assertion = mcpAssertion([], 'not-filed', $foreign);
    $credential = mcpStoreCredential($assertion, abilities: [OperatorAbility::McpRead->value]);

    // Prefix selects assertion exclusively even though these exact bytes are
    // also a resolvable unified credential.
    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$assertion])
        ->assertUnauthorized();

    expect($credential->refresh()->last_used_at)->toBeNull()
        ->and(CredentialAuditEvent::query()->where('credential_id', $credential->id)->count())->toBe(0)
        ->and(mcpRefusalReasons())->toBe([AssertionRefusalReason::UnknownKey->value]);
});

it('does not answer or audit a downstream refusal as this door refusing', function (): void {
    // Authentication here SUCCEEDS — the burn happens, the principal is
    // published — and the tool behind the door then refuses an assertion
    // of its own. That refusal belongs to the tool: this middleware must
    // not catch it, answer its uniform 401 as though this request never
    // authenticated, or write a denied_action row claiming it did.
    mcpRequest()->assertOk();

    $this->postJson('/mcp-downstream-refusal', [], [
        'Authorization' => 'Bearer '.mcpAssertion(['sub' => 'downstream-subject']),
    ])->assertServerError();

    expect(AssertionBurn::query()->count())->toBe(2)
        ->and(mcpRefusalReasons())->toBe([]);
});

it('takes the bearer out of the request before a refusal is served or a fault throws', function (): void {
    // The scrub's promise is ORDERING, not just occurrence: the
    // credential leaves the request object BEFORE verification or
    // storage can throw, because the failure scenario that created the
    // rule was precisely a refusal or a database exception serialized
    // by a rich reporter — the paths the success-path test cannot see.
    // Driving the middleware directly means the SAME Request object
    // can be inspected after each outcome, which a feature request
    // cannot reach.
    $next = static fn (Request $r): SymfonyResponse => response()->json(['ok' => true]);

    // A CAUGHT refusal — an unknown key id — answers the uniform 401
    // through the normal pipeline.
    $unknownKey = mcpAssertion([], 'not-filed', consoleKeypair());
    $refused = Request::create('/mcp', 'POST', server: [
        'HTTP_AUTHORIZATION' => 'Bearer '.$unknownKey,
        'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer '.$unknownKey,
        'HTTP_ACCEPT' => 'application/json',
    ]);

    $response = app(AuthenticateMcp::class)->handle($refused, $next);

    expect($response->getStatusCode())->toBe(AuthenticateMcp::REFUSAL_STATUS)
        ->and($refused->headers->get('Authorization'))->toBeNull()
        ->and($refused->server->get('HTTP_AUTHORIZATION'))->toBeNull()
        ->and($refused->server->get('REDIRECT_HTTP_AUTHORIZATION'))->toBeNull();

    // An UNCAUGHT storage fault — the fail-closed audit write cannot
    // commit — propagates out of handle(), and the Request it leaves
    // behind is scrubbed all the same.
    Schema::drop('credential_audit_events');

    $unauditable = mcpAssertion(['aud' => 'https://another-deployment.test']);
    $thrown = Request::create('/mcp', 'POST', server: [
        'HTTP_AUTHORIZATION' => 'Bearer '.$unauditable,
        'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer '.$unauditable,
        'HTTP_ACCEPT' => 'application/json',
    ]);

    try {
        app(AuthenticateMcp::class)->handle($thrown, $next);
        $this->fail('The refusal whose audit could not commit should have failed closed.');
    } catch (Throwable) {
        // Expected: the audit transaction could not commit.
    }

    expect($thrown->headers->get('Authorization'))->toBeNull()
        ->and($thrown->server->get('HTTP_AUTHORIZATION'))->toBeNull()
        ->and($thrown->server->get('REDIRECT_HTTP_AUTHORIZATION'))->toBeNull();
});

it('fails closed when an assertion refusal cannot be audited', function (): void {
    Schema::drop('credential_audit_events');

    mcpRequest(['aud' => 'https://another-deployment.test'])->assertServerError();
});
