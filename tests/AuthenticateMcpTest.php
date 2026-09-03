<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Scope;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);

    Route::post('/mcp-probe', function (Request $request): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();
        $audit = $acting->check() ? AppActionActor::fromActingPrincipal($acting) : null;
        $user = $request->user();
        $userId = match (true) {
            $user instanceof DelegatedActor => $user->getAuthIdentifier(),
            $user instanceof ApiToken => $user->getKey(),
            default => null,
        };

        return [
            'user_type' => is_object($user) ? $user::class : null,
            'user_id' => $userId,
            'actor_token_id' => $request->attributes->get('bfc.actor_token_id'),
            'acting_id' => $acting->identifier(),
            'delegated' => $acting->delegated,
            'guard' => $acting->guard,
            'role' => $acting->role?->value,
            'on_behalf_of' => $acting->onBehalfOf,
            'audit_type' => $audit?->type->value,
            'audit_ref' => $audit?->ref,
            'audit_agency' => $audit?->onBehalfOf,
            'authorization' => $request->header('Authorization'),
            'server_authorization' => $request->server->get('HTTP_AUTHORIZATION'),
            'redirect_server_authorization' => $request->server->get('REDIRECT_HTTP_AUTHORIZATION'),
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
        throw AssertionRefused::because(AssertionRefusalReason::Replayed);
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

it('publishes the assertion actor and this handoff claims for this request only', function (): void {
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
        ->assertJsonPath('authorization', null);

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
    $session = $this->withSession(['sentinel' => 'kept'])
        ->postJson('/mcp-session-probe', [], ['Authorization' => 'Bearer '.mcpAssertion()])
        ->assertOk()
        ->json();

    expect($session)->toHaveKey('sentinel', 'kept')
        ->not->toHaveKey(consoleGuardSessionKey())
        ->not->toHaveKey(ConsoleSession::ASSERTION_ISSUED_AT)
        ->not->toHaveKey(ConsoleSession::DISPLAY_NAME)
        ->not->toHaveKey(ConsoleSession::ROLE)
        ->not->toHaveKey(ConsoleSession::ON_BEHALF_OF);
});

it('authenticates a TokenRegistry bearer and does not leak the prior request assertion memo', function (): void {
    mcpRequest(['sub' => 'first-request'])->assertOk();

    $plaintext = 'registry-'.bin2hex(random_bytes(16));
    $token = ApiToken::query()->create([
        'name' => 'mcp registry token',
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => ['apps:call'],
    ]);

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$plaintext])
        ->assertOk()
        ->assertJsonPath('user_type', ApiToken::class)
        ->assertJsonPath('user_id', $token->getKey())
        ->assertJsonPath('acting_id', null)
        ->assertJsonPath('delegated', false);
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

it('grants the admin actor attribute only to an admin-scoped registry token', function (): void {
    // A non-admin, MCP-scoped token authenticates this door — that is
    // the point of a per-tool gate — but `bfc.actor_token_id` means
    // "an ADMIN token authenticated" (EnsureAdminToken's convention;
    // six package readers convert it straight into an admin audit
    // actor), so a token without the scope must not carry it.
    $limited = 'non-admin-'.bin2hex(random_bytes(16));
    $limitedToken = ApiToken::query()->create([
        'name' => 'mcp non-admin token',
        'token_hash' => hash('sha256', $limited),
        'abilities' => ['apps:call'],
    ]);

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$limited])
        ->assertOk()
        ->assertJsonPath('user_type', ApiToken::class)
        ->assertJsonPath('user_id', $limitedToken->getKey())
        ->assertJsonPath('actor_token_id', null);

    $admin = 'admin-'.bin2hex(random_bytes(16));
    $adminToken = ApiToken::query()->create([
        'name' => 'mcp admin token',
        'token_hash' => hash('sha256', $admin),
        'abilities' => [Scope::Admin->value],
    ]);

    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$admin])
        ->assertOk()
        ->assertJsonPath('actor_token_id', (string) $adminToken->getKey());
});

it('never falls through between registry and assertion authentication paths', function (): void {
    // An ordinary invalid bearer is never parsed or assertion-audited.
    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer not-an-assertion'])
        ->assertUnauthorized();

    $foreign = consoleKeypair();
    $assertion = mcpAssertion([], 'not-filed', $foreign);
    $token = ApiToken::query()->create([
        'name' => 'collision witness',
        'token_hash' => hash('sha256', $assertion),
        'abilities' => ['apps:call'],
    ]);

    // Prefix selects assertion exclusively even though these exact bytes are
    // also a resolvable registry token.
    $this->postJson('/mcp-probe', [], ['Authorization' => 'Bearer '.$assertion])
        ->assertUnauthorized();

    expect($token->refresh()->request_count)->toBe(0)
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

it('keeps a refused console session terminal over a published request assertion', function (): void {
    // The one fixture carrying BOTH a console session the guard refuses
    // (a capped one — ConsoleSessionClock's 120-minute absolute cap)
    // and a verified, published request assertion. The resolver's
    // refusal branch sits ABOVE its request-assertion branch; moving
    // the branches would let this assertion rescue the request, which
    // is exactly the ordering this test exists to pin. A just-refused
    // delegated session resolves NOBODY: never the assertion principal,
    // never a union.
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()))
        ->postJson('/mcp-precedence-probe', [], [
            'Authorization' => 'Bearer '.mcpAssertion(['sub' => 'assertion-rescue-attempt']),
        ])
        ->assertOk()
        ->assertJsonPath('refused', true)
        ->assertJsonPath('principal', null)
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('delegated_session_present', true);
});

it('fails closed when an assertion refusal cannot be audited', function (): void {
    Schema::drop('credential_audit_events');

    mcpRequest(['aud' => 'https://another-deployment.test'])->assertServerError();
});
