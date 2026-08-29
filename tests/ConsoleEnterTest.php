<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryState;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Login;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\HttpFoundation\Cookie;

uses(RefreshDatabase::class);

/**
 * `POST /bfc/console/enter` — the door (Console PRD D12/D13, PR4).
 *
 * Every test here drives the REAL route: the vendor's two form fields
 * in, a `303` to a relative path or one uniform `403` out. Nothing
 * seeds a session by hand, because the whole point of this PR is that
 * the endpoint is the thing that creates one.
 */
beforeEach(function (): void {
    // The production shape a landed operator meets: `bfc.console` in
    // front of `auth:bfc-console`, so the delegated principal is the
    // principal of the route.
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/console-landed', fn (): array => [
            'principal' => app(ActingPrincipalResolver::class)->resolve()->identifier(),
            'attribution' => app(ActingPrincipalResolver::class)->resolve()->attribution,
        ]);
});

/**
 * Post a handoff the way the vendor's auto-submit form would.
 *
 * @param  array{assertion: string, state: string}  $handoff
 */
function consoleEnter(array $handoff): TestResponse
{
    return test()->post('/bfc/console/enter', $handoff);
}

/**
 * Continue the browser session the enter response just established, by
 * replaying the session cookie it set. This is the only honest way to
 * assert that the endpoint MINTED a session rather than merely writing
 * some keys: the next request has to rehydrate it.
 */
function consoleFollow(TestResponse $entered, string $uri = '/console-landed'): TestResponse
{
    $cookie = $entered->getCookie((string) config('session.cookie'));

    expect($cookie)->not->toBeNull();

    return test()->withCookie((string) config('session.cookie'), (string) $cookie?->getValue())->getJson($uri);
}

/**
 * Every refusal the audit stream recorded, keyed by its bounded reason.
 *
 * Keyed rather than ordered: `occurred_at` has one-second granularity
 * and the ids are uuids, so several refusals inside one test have no
 * stable order to assert on — and the reason is what the assertions are
 * about anyway.
 *
 * @return array<string, CredentialAuditEvent>
 */
function consoleEntryRefusals(): array
{
    return CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get()
        ->keyBy(fn (CredentialAuditEvent $event): string => str_replace(ConsoleEnter::AUDIT_NOTE, '', (string) $event->note))
        ->all();
}

/**
 * The bounded reasons the refusal audit recorded, in no particular
 * order.
 *
 * @return list<string>
 */
function consoleEntryRefusalReasons(): array
{
    $reasons = array_keys(consoleEntryRefusals());

    sort($reasons);

    return $reasons;
}

// ─── AC1: a valid handoff enters and lands ──────────────────────────────────

it('mints a delegated session from a valid handoff and lands on the requested relative path', function (): void {
    $entered = consoleEnter(consoleHandoff('/orders?tab=open'));

    $entered->assertStatus(303)->assertHeader('Location', '/orders?tab=open');

    // The session it handed back really carries the delegated actor —
    // asserted by USING it on a route the console guard governs, not by
    // reading session keys.
    $actor = DelegatedActor::query()->sole();

    consoleFollow($entered)
        ->assertOk()
        ->assertJsonPath('principal', 'bfc-console:'.$actor->getKey())
        ->assertJsonPath('attribution', 'Jane Operator');

    expect($actor->last_handoff_role)->toBe(ConsoleRole::Admin)
        ->and(AssertionBurn::query()->count())->toBe(1);
});

it('carries the handoff its own role and agency into the session, not the row\'s', function (): void {
    $entered = consoleEnter(consoleHandoff('/', [
        'role' => ConsoleRole::Member->value,
        'on_behalf_of' => 'Acme Agency',
    ]));

    $entered->assertStatus(303)->assertHeader('Location', '/');

    consoleFollow($entered)->assertOk()->assertJsonPath('attribution', 'Jane Operator (Acme Agency)');
});

// ─── AC2: the single-use burn ───────────────────────────────────────────────

it('refuses a genuine second presentation of the same assertion, because the mint id is spent', function (): void {
    $handoff = consoleHandoff('/orders');

    consoleEnter($handoff)->assertStatus(303);

    // The SAME bytes, presented again — a replay, not a second mint.
    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::Replayed->value])
        ->and(AssertionBurn::query()->count())->toBe(1);
});

it('length-delimits the burn key, so two different issuer and mint pairs cannot hash alike', function (): void {
    // Without the lengths, one issuer's suffix and the next mint id's
    // prefix concatenate to the same string, and a collision here would
    // refuse a GENUINE assertion as a replay of somebody else's. Only
    // one issuer is trusted in v1 (D18), so this is a property of the
    // key rather than a reachable flow, and it is asserted as one.
    expect(AssertionBurn::mintHash('https://a.test', 'bc'))
        ->not->toBe(AssertionBurn::mintHash('https://a.testb', 'c'))
        ->and(AssertionBurn::mintHash('https://a.test', 'm1'))
        ->toBe(AssertionBurn::mintHash('https://a.test', 'm1'));
});

// ─── AC3 / AC4: the deployment audience and the clock ───────────────────────

it('refuses an assertion minted for another deployment', function (): void {
    consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([AssertionRefusalReason::AudienceMismatch->value])
        ->and(DelegatedActor::query()->count())->toBe(0);
});

it('refuses an assertion whose expiry has passed', function (): void {
    $now = CarbonImmutable::now();

    consoleEnter(consoleHandoff('/orders', [
        'iat' => $now->subSeconds(200)->toAtomString(),
        'nbf' => $now->subSeconds(200)->toAtomString(),
        'exp' => $now->subSeconds(110)->toAtomString(),
    ]))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([AssertionRefusalReason::Expired->value])
        ->and(DelegatedActor::query()->count())->toBe(0);
});

it('refuses an actor this deployment has contained, and says so in the audit', function (): void {
    // The issuer still vouches for the human; this deployment does not.
    consoleEnter(consoleHandoff('/orders'))->assertStatus(303);

    DelegatedActor::query()->sole()->deactivate();

    consoleEnter(consoleHandoff('/orders'))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::ActorDeactivated->value]);
});

it('keeps the handoff record of a contained human who tried to enter', function (): void {
    // PR3 commits the handoff record before the decision precisely so a
    // refusal cannot roll it back. Nesting redeem()'s transaction inside
    // the burn's would have undone that, so the endpoint records it
    // outside — and this is what says so.
    consoleEnter(consoleHandoff('/orders'))->assertStatus(303);

    $actor = DelegatedActor::query()->sole();
    $actor->deactivate();

    consoleEnter(consoleHandoff('/orders', ['display_name' => 'Jane Renamed']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(DelegatedActor::query()->sole()->last_handoff_display_name)->toBe('Jane Renamed');
});

// ─── AC5: audited, actor-typed, and answered identically ────────────────────

it('types the actor on every refusal, and names the mint only when it verified', function (): void {
    // A verifier refusal knows no mint id and does not guess one; a
    // post-verification refusal names the jti it actually read.
    consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    $handoff = consoleHandoff('/orders');
    consoleEnter($handoff)->assertStatus(303);
    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    $refusals = consoleEntryRefusals();

    $verifierRefusal = $refusals[AssertionRefusalReason::AudienceMismatch->value];
    $burnRefusal = $refusals[ConsoleEntryRefusalReason::Replayed->value];

    expect($refusals)->toHaveCount(2)
        ->and($verifierRefusal->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($verifierRefusal->actor_ref)->toBeNull()
        ->and($burnRefusal->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($burnRefusal->actor_ref)->toBeString()
        ->and($burnRefusal->actor_ref)->toStartWith('mint_');
});

it('answers a replayed, a wrong-deployment and an expired assertion with byte-identical responses', function (): void {
    $now = CarbonImmutable::now();

    $spent = consoleHandoff('/orders');
    consoleEnter($spent)->assertStatus(303);

    $replayed = consoleEnter($spent);
    $wrongDeployment = consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']));
    $expired = consoleEnter(consoleHandoff('/orders', [
        'iat' => $now->subSeconds(200)->toAtomString(),
        'nbf' => $now->subSeconds(200)->toAtomString(),
        'exp' => $now->subSeconds(110)->toAtomString(),
    ]));

    $responses = [$replayed, $wrongDeployment, $expired];

    foreach ($responses as $response) {
        expect($response->getStatusCode())->toBe($replayed->getStatusCode())
            ->and($response->getContent())->toBe($replayed->getContent());
    }

    // The three refusals ARE distinguishable in the audit stream, which
    // is the whole point of collapsing them on the wire.
    expect(consoleEntryRefusalReasons())->toBe([
        AssertionRefusalReason::AudienceMismatch->value,
        AssertionRefusalReason::Expired->value,
        ConsoleEntryRefusalReason::Replayed->value,
    ]);

    // Headers too, except the three that legitimately differ: the
    // throttle's own counter (it counts requests, not reasons), the
    // session cookie (a fresh id per request), and the clock.
    $ignored = ['set-cookie', 'x-ratelimit-remaining', 'date'];

    $shape = static fn (TestResponse $response): array => array_diff_key(
        $response->baseResponse->headers->all(),
        array_flip($ignored),
    );

    foreach ($responses as $response) {
        expect($shape($response))->toBe($shape($replayed));
    }

    // `set-cookie` is excluded above because a session id rotates per
    // request — but excluding the whole header would hide a difference
    // in cookie PRESENCE between refusal paths, which would be a real
    // distinguisher. So the cookie NAMES are compared explicitly, and
    // the only thing left unpinned is the rotating value itself.
    $cookieNames = static function (TestResponse $response): array {
        $names = array_map(
            static fn (Cookie $cookie): string => $cookie->getName(),
            $response->baseResponse->headers->getCookies(),
        );

        sort($names);

        return $names;
    };

    foreach ($responses as $response) {
        expect($cookieNames($response))->toBe($cookieNames($replayed));
    }
});

it('says nothing about the reason in the body it hands back', function (): void {
    $response = consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']));

    $response->assertStatus(ConsoleEnter::REFUSAL_STATUS)
        ->assertExactJson(['version' => ConsoleEnter::PAYLOAD_VERSION, 'error' => ConsoleEnter::REFUSAL_ERROR]);

    foreach ([...AssertionRefusalReason::values(), ...ConsoleEntryRefusalReason::values()] as $reason) {
        expect((string) $response->getContent())->not->toContain($reason);
    }
});

// ─── AC6: the return path ───────────────────────────────────────────────────

it('refuses a return path that is not a safe same-origin relative path, whatever the mint signed', function (string $returnTo): void {
    consoleEnter(consoleHandoff($returnTo))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::ReturnPathRefused->value])
        ->and(AssertionBurn::query()->count())->toBe(0);
})->with([
    'absolute https' => ['https://evil.example/x'],
    'absolute http' => ['http://evil.example/x'],
    'protocol relative' => ['//evil.example/x'],
    'a scheme that is not a location' => ['javascript:alert(1)'],
    'not rooted' => ['orders'],
    'a backslash' => ['/\\evil.example'],
    'an encoded double slash' => ['/%2f%2fevil.example'],
    'a double-encoded double slash' => ['/%252f%252fevil.example'],
    'an encoded backslash' => ['/%5cevil.example'],
    'a CRLF pair' => ["/orders\r\nSet-Cookie: a=b"],
    'empty' => [''],
]);

it('honours a configured return-path allowlist, at a segment boundary', function (): void {
    config(['built-for-cloud.console.return_path_allowlist' => ['/admin']]);

    consoleEnter(consoleHandoff('/admin/users?page=2'))
        ->assertStatus(303)
        ->assertHeader('Location', '/admin/users?page=2');

    consoleEnter(consoleHandoff('/admin-secrets'))->assertStatus(ConsoleEnter::REFUSAL_STATUS);
    consoleEnter(consoleHandoff('/orders'))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::ReturnPathRefused->value])
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::DeniedAction->value)->count())
        ->toBe(2);
});

it('refuses a return path carrying a traversal segment in any decoded form, allowlist or no allowlist', function (string $returnTo): void {
    // THE DEFECT THIS CLOSES. `/admin/../billing` is a legitimately
    // relative path — every syntactic check passes — it matched the
    // `/admin` prefix, and the BROWSER then resolved it to `/billing`.
    // The configured landing restriction was bypassed with a value
    // nothing had rejected. The encoded forms were the same defect one
    // and two layers down.
    config(['built-for-cloud.console.return_path_allowlist' => ['/admin']]);

    consoleEnter(consoleHandoff($returnTo))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    // Refused with no allowlist configured at all, too: a path whose
    // meaning depends on who normalizes it is not a redirect target.
    config(['built-for-cloud.console.return_path_allowlist' => []]);

    consoleEnter(consoleHandoff($returnTo))->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::ReturnPathRefused->value])
        ->and(AssertionBurn::query()->count())->toBe(0);
})->with([
    'raw traversal' => ['/admin/../billing'],
    'encoded traversal' => ['/admin/%2e%2e/billing'],
    'double-encoded traversal' => ['/admin/%252e%252e/billing'],
    'a single dot segment' => ['/admin/./billing'],
    'traversal above the root' => ['/../billing'],
    'a trailing traversal' => ['/admin/..'],
    // The delimiter is INVENTED by decoding. There is no literal `?` in
    // the value, so the browser treats `%3F` as an ordinary path
    // character and resolves the `%2e%2e` — while a check that split the
    // query off each decoded form saw only `/admin`.
    'a traversal hidden behind an encoded question mark' => ['/admin%3F/%2e%2e/billing'],
    'a traversal hidden behind an encoded hash' => ['/admin%23/%2e%2e/billing'],
    'the same, double-encoded' => ['/admin%253F/%252e%252e/billing'],
    'a raw traversal behind an encoded question mark' => ['/admin%3F/../billing'],
]);

it('leaves a dot inside a segment alone, because that is an ordinary path', function (string $returnTo): void {
    // The rule is about SEGMENTS. Refusing every path with a dot in it
    // would cost a caller `/reports..csv` for nothing.
    consoleEnter(consoleHandoff($returnTo))
        ->assertStatus(303)
        ->assertHeader('Location', $returnTo);
})->with([
    'a dotted filename' => ['/reports..csv'],
    'dots inside a word' => ['/o..ders'],
    'dots in the query string' => ['/orders?sort=..'],
    'dots in the fragment' => ['/orders#..'],
]);

it('matches the allowlist against the fully decoded path, not the raw one', function (): void {
    // `/%61dmin/users` and `/admin/users` are the same path; an
    // allowlist comparing raw strings would answer differently for them.
    // The REDIRECT still emits what the issuer signed, verbatim.
    config(['built-for-cloud.console.return_path_allowlist' => ['/admin']]);

    consoleEnter(consoleHandoff('/%61dmin/users'))
        ->assertStatus(303)
        ->assertHeader('Location', '/%61dmin/users');
});

it('establishes the path once, so a query string cannot appear out of a decoding round', function (): void {
    // The canonical path is split off the RAW value. A `?` that only
    // exists after decoding is an ordinary path character — which is
    // what a browser thinks it is too — so it can neither shorten the
    // path a decision is made about nor hide anything behind itself.
    expect(ConsoleReturnTo::canonicalPath('/orders?sort=..'))->toBe('/orders')
        ->and(ConsoleReturnTo::canonicalPath('/orders#..'))->toBe('/orders')
        ->and(ConsoleReturnTo::canonicalPath('/%61dmin/users'))->toBe('/admin/users')
        // No literal delimiter: the whole string is the path, and the
        // traversal inside it is seen.
        ->and(ConsoleReturnTo::canonicalPath('/admin%3F/%2e%2e/billing'))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath('/admin%23/%2e%2e/billing'))->toBeNull()
        // A decoded `?` inside the path is kept, not treated as a cut.
        ->and(ConsoleReturnTo::canonicalPath('/admin%3Fx'))->toBe('/admin?x')
        ->and(ConsoleReturnTo::relative('/admin%3F/%2e%2e/billing'))->toBeNull();
});

it('refuses an allowlist prefix that is not itself a safe in-app path, rather than widening on it', function (array $allowlist): void {
    // A typo must never widen an allowlist. `//` is the one that
    // mattered: it used to `rtrim()` to the empty string, which was the
    // WILDCARD branch, so a configured `//` silently allowed every
    // path. Only a literal `/` reaches that branch now.
    config(['built-for-cloud.console.return_path_allowlist' => $allowlist]);

    consoleEnter(consoleHandoff('/orders'))->assertStatus(ConsoleEnter::REFUSAL_STATUS);
})->with([
    'an absolute url' => [['https://evil.example']],
    'not rooted' => [['orders']],
    'a protocol-relative prefix' => [['//']],
    'a longer protocol-relative prefix' => [['//evil.example']],
    'several slashes' => [['///']],
    'a traversing prefix' => [['/..']],
    'not a string at all' => [[42]],
]);

it('treats a literal root prefix as the wildcard it looks like', function (): void {
    // The one prefix that legitimately covers everything, and now the
    // only one that can.
    config(['built-for-cloud.console.return_path_allowlist' => ['/']]);

    consoleEnter(consoleHandoff('/orders'))->assertStatus(303)->assertHeader('Location', '/orders');
});

it('canonicalizes the configured prefixes the same way it canonicalizes the path', function (): void {
    // One door for both sides of the comparison: a prefix spelled with
    // a percent-encoded character or a trailing slash means what it
    // looks like.
    config(['built-for-cloud.console.return_path_allowlist' => ['/adm%69n/']]);

    consoleEnter(consoleHandoff('/admin/users'))->assertStatus(303);
    consoleEnter(consoleHandoff('/orders'))->assertStatus(ConsoleEnter::REFUSAL_STATUS);
});

// ─── AC7: the signed state ──────────────────────────────────────────────────

it('refuses an entry whose state was tampered with after the mint signed it', function (): void {
    $handoff = consoleHandoff('/orders');
    $handoff['state'] = consoleStatePayload('/somewhere-else');

    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::StateMismatch->value]);
});

it('refuses an entry that presents no state at all', function (mixed $state, string $reason): void {
    $handoff = consoleHandoff('/orders');
    $handoff['state'] = $state;

    consoleEnter(array_filter($handoff, static fn (mixed $value): bool => $value !== null))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([$reason]);
})->with([
    'absent' => [null, ConsoleEntryRefusalReason::StateMissing->value],
    'empty' => ['', ConsoleEntryRefusalReason::StateMissing->value],
]);

it('refuses a mint that signed no state, whatever state is presented', function (): void {
    $handoff = consoleHandoff('/orders', ['state' => consoleAbsent()]);

    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::StateUnsigned->value]);
});

it('refuses a state lifted from a different mint', function (): void {
    $first = consoleHandoff('/orders');
    $second = consoleHandoff('/reports');

    // The second mint's token, carrying the first mint's state — the
    // shape a captured state takes.
    consoleEnter(['assertion' => $second['assertion'], 'state' => $first['state']])
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::StateMismatch->value]);
});

it('refuses a state the mint signed but nothing can decode', function (string $state, string $reason): void {
    $handoff = consoleHandoff('/orders', [], $state);

    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([$reason]);
})->with([
    'not base64url' => ['!!!not base64!!!', ConsoleEntryRefusalReason::StateMalformed->value],
    'not json' => [Base64UrlSafe::encodeUnpadded('not json at all'), ConsoleEntryRefusalReason::StateMalformed->value],
    'json that is not an object' => [Base64UrlSafe::encodeUnpadded('"a string"'), ConsoleEntryRefusalReason::StateMalformed->value],
    'no return_to' => [Base64UrlSafe::encodeUnpadded('{"roster":[]}'), ConsoleEntryRefusalReason::ReturnPathRefused->value],
    'over the bound' => [str_repeat('a', ConsoleEntryState::MAX_LENGTH + 1), ConsoleEntryRefusalReason::StateMalformed->value],
]);

it('ignores members of the state it does not know, so the issuer can grow the payload', function (): void {
    $state = Base64UrlSafe::encodeUnpadded((string) json_encode([
        ConsoleEntryState::RETURN_TO => '/orders',
        'roster' => [['name' => 'sink'], ['name' => 'hone']],
    ], JSON_THROW_ON_ERROR));

    consoleEnter(consoleHandoff('/ignored', [], $state))
        ->assertStatus(303)
        ->assertHeader('Location', '/orders');
});

it('refuses a mint whose state claim is not a digest at all', function (): void {
    // The VERIFIER refuses this one — a present-but-malformed binding is
    // a claim-shape failure, never a silent "no state".
    consoleEnter(consoleHandoff('/orders', ['state' => 'not-a-digest']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([AssertionRefusalReason::InvalidClaims->value]);
});

it('refuses a request that carries no assertion at all', function (mixed $assertion): void {
    $handoff = consoleHandoff('/orders');
    $handoff['assertion'] = $assertion;

    consoleEnter(array_filter($handoff, static fn (mixed $value): bool => $value !== null))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::MissingAssertion->value]);
})->with([
    'absent' => [null],
    'empty' => [''],
]);

// ─── AC8: the carrier ───────────────────────────────────────────────────────

it('does not route GET at the enter path, so an assertion can never ride a query string', function (): void {
    // 405, not 404: the path exists and the VERB does not, which is the
    // difference between "this deployment has no console" and "a link
    // was built wrong".
    $this->get('/bfc/console/enter?assertion=x')->assertStatus(405);
    $this->putJson('/bfc/console/enter')->assertStatus(405);
});

// ─── AC9: the limiter ───────────────────────────────────────────────────────

it('rate-limits the door', function (): void {
    $handoff = consoleHandoff('/orders', ['aud' => 'https://someone-else.test']);

    // The limit is per minute, per IP, and refusals spend it too — the
    // throttle sits OUTSIDE everything else on the route.
    foreach (range(1, 30) as $ignored) {
        consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);
    }

    consoleEnter($handoff)->assertStatus(429);
});

// ─── The refusal audit fails CLOSED ─────────────────────────────────────────

it('records every refusal it serves, one row per refused entry', function (): void {
    foreach (range(1, 3) as $ignored) {
        consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
            ->assertStatus(ConsoleEnter::REFUSAL_STATUS);
    }

    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::DeniedAction->value)->count())
        ->toBe(3);
});

it('does not serve a refusal it could not record', function (): void {
    // An earlier revision swallowed every audit failure and answered
    // 403 anyway — so an attacker probing during an audit-store outage
    // left NO evidence, while the contract promised every refusal was
    // recorded. It fails closed now: no audit row, no ordinary refusal.
    //
    // The outage is driven for real rather than mocked: the outbox half
    // of the stream is gone, so the recorder's second insert throws and
    // takes the audit row down with it — a partial audit-store failure,
    // which is the shape that actually happens.
    Schema::drop('credential_outbox');

    consoleEnter(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
        ->assertStatus(500);

    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::DeniedAction->value)->count())
        ->toBe(0);
});

// ─── AC11: the burn is atomic with the redemption ───────────────────────────

it('rolls the burn back with the redemption, so the two commit or fail together', function (): void {
    // The genuine race cannot be driven in-process on sqlite (see the
    // mutation-debt row for bfc#pr4). What CAN be driven, and is the
    // property the race rests on, is that the burn row and the session
    // live in ONE transaction: a redemption that fails after the burn
    // must leave no spent mint and no session behind.
    //
    // EVERY ASSERTION BELOW LOOKS AT STATE. An earlier revision of this
    // test asserted only that the exception propagated, which is a body
    // that would stay green with the transaction removed entirely — a
    // test named for the atomicity guarantee that could not detect its
    // absence.
    Event::listen(Login::class, function (): never {
        throw new RuntimeException('an audit backend that is down');
    });

    $handoff = consoleHandoff('/orders');

    $failed = consoleEnter($handoff);
    $failed->assertStatus(500);

    // The burn rolled back with the redemption…
    expect(AssertionBurn::query()->count())->toBe(0);

    // …the session the redemption had begun writing is not usable…
    consoleFollow($failed)->assertStatus(401)->assertHeader('BFC-Console-Reentry', '1');

    // …and because the mint was never spent, a later presentation of the
    // SAME assertion is not a replay. That is the direction that makes
    // this safe rather than merely tidy, and it is also what proves the
    // row is genuinely absent rather than merely uncounted.
    Event::forget(Login::class);

    consoleEnter($handoff)->assertStatus(303);

    expect(AssertionBurn::query()->count())->toBe(1);
});

it('keys the burn on a unique index, which is what makes it atomic', function (): void {
    // The index is the check. A read-then-write would leave exactly the
    // window single-use exists to close.
    expect(Schema::hasTable('bfc_console_assertion_burns'))->toBeTrue();

    $indexes = collect(Schema::getIndexes('bfc_console_assertion_burns'))
        ->filter(fn (array $index): bool => $index['unique'] === true)
        ->flatMap(fn (array $index): array => $index['columns'])
        ->all();

    expect($indexes)->toContain('mint_hash');
});

// ─── Housekeeping ───────────────────────────────────────────────────────────

it('sits exactly on the prune boundary: one second inside keeps a burn row, one second past drops it', function (): void {
    // The boundary is the assertion's own life plus the margin, and the
    // margin points ONE WAY on purpose: a row dropped while its
    // assertion could still be presented would UN-SPEND a mint. An
    // earlier revision travelled 100s against a 150s boundary, so the
    // constant could have been almost any value and the test would
    // still have passed. This sits on it from both sides.
    $start = CarbonImmutable::parse('2026-08-29T12:00:00+00:00');
    // consoleClaims() mints `exp` 90 seconds after `iat`.
    $boundary = 90 + AssertionBurn::PRUNE_MARGIN_SECONDS;

    $this->travelTo($start);

    consoleEnter(consoleHandoff('/orders'))->assertStatus(303);

    $spent = AssertionBurn::query()->sole()->mint_id;

    // ON the boundary: still inside the margin, still kept.
    $this->travelTo($start->addSeconds($boundary));

    consoleEnter(consoleHandoff('/reports'))->assertStatus(303);

    expect(AssertionBurn::query()->pluck('mint_id')->all())->toContain($spent);

    // One second past it: the row can no longer change any answer.
    $this->travelTo($start->addSeconds($boundary + 1));

    consoleEnter(consoleHandoff('/invoices'))->assertStatus(303);

    expect(AssertionBurn::query()->pluck('mint_id')->all())->not->toContain($spent)
        // …and the rows still inside their own windows are untouched.
        ->and(AssertionBurn::query()->count())->toBe(2);
});

// ─── A contained actor's mint is deliberately NOT spent ─────────────────────

it('leaves a contained actor\'s mint unspent, so every attempt audits as containment', function (): void {
    // A DELIBERATE CHOICE, not an accident of the transaction shape.
    // The containment refusal is thrown inside the burn's transaction,
    // so it rolls the burn back and the assertion stays presentable
    // until its TTL runs out — every presentation refused, every one
    // audited as `actor_deactivated`.
    //
    // Spending the mint instead would make the SECOND attempt audit as
    // `replayed`, which says "this token was already redeemed". It was
    // not. An operator reading the trail of an offboarded human's
    // attempts to get back in would see one containment and a run of
    // replays, and reasonably conclude the token had worked once.
    consoleEnter(consoleHandoff('/orders'))->assertStatus(303);

    DelegatedActor::query()->sole()->deactivate();

    $handoff = consoleHandoff('/orders');

    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);
    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);
    consoleEnter($handoff)->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    // Only the successful entry spent a mint.
    expect(AssertionBurn::query()->count())->toBe(1);

    // And all three attempts are recorded as what they were.
    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::DeniedAction->value)->count())
        ->toBe(3)
        ->and(consoleEntryRefusalReasons())->toBe([ConsoleEntryRefusalReason::ActorDeactivated->value]);
});

// ─── The contract face ──────────────────────────────────────────────────────

it('advertises the door as a capability', function (): void {
    // Named for what ships, like `console-keys` and `console-vitals`
    // before it: a control plane reading this knows it may hand an
    // operator to this deployment, which is a promise the route keeps.
    expect($this->getJson('/bfc/meta')->assertOk()->json('capabilities'))
        ->toContain('console-enter')
        ->toContain('console-guard');
});
