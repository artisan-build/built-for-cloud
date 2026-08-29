<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReentryReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSessionClock;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * D7 (amended): the sliding idle window is Laravel's own; the ABSOLUTE
 * assertion-age cap is this package's, it is enforced AT THE GUARD by
 * server-side session invalidation, and it fails closed on every marker
 * it cannot read. The enter endpoint that writes the marker is PR4's, so
 * these tests seed the session directly — which is also the only way to
 * reach the fail-closed cases at all.
 *
 * The route stack below is the production shape: `bfc.console` in FRONT
 * of `auth:bfc-console`, so a refused or absent session gets the
 * structured re-entry 401 rather than the framework's generic one, and a
 * live one goes on to have the console guard made the guard OF THE
 * ROUTE.
 *
 * Every test that sits on a clock boundary freezes time first: the cap
 * is measured in whole seconds against `now`, so a test that seeds
 * `now − 7199` from the real wall clock and lets the request read `now`
 * again flips to a refusal whenever the request crosses a second.
 */
beforeEach(function (): void {
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/console-guarded', fn (): array => [
            'ok' => true,
            'principal' => app(ActingPrincipalResolver::class)->resolve()->identifier(),
        ]);

    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->post('/livewire/update', fn (): array => ['ok' => true]);

    // Deliberately WITHOUT the gate and without the console guard. The
    // cap lives in the GUARD, so this route must reach exactly the same
    // verdict — including destroying the session — with no console
    // middleware anywhere near it.
    Route::middleware([StartSession::class])->get('/console-ungated', function (): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        return [
            'delegated' => $acting->delegated,
            'delegated_session_present' => $acting->delegatedSessionPresent(),
            'principal' => $acting->identifier(),
            'attribution' => $acting->attribution,
        ];
    });
});

function cappedUser(): User
{
    return User::query()->create([
        'name' => 'Local User',
        'email' => 'local@example.com',
        'password' => 'irrelevant',
    ]);
}

/**
 * A fixed instant, so a boundary test is a boundary test rather than a
 * race with the clock.
 */
function cappedNow(): CarbonImmutable
{
    return CarbonImmutable::parse('2026-08-29T12:00:00+00:00');
}

// ─── The cap itself ─────────────────────────────────────────────────────────

it('lets a fresh delegated session through', function (): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-guarded')
        ->assertOk()
        ->assertJsonPath('principal', 'bfc-console:'.$actor->getKey());
});

it('sits exactly on the cap boundary: one second inside passes, the boundary itself refuses', function (): void {
    $this->travelTo(cappedNow());

    $actor = consoleActor();
    $capSeconds = ConsoleSessionClock::ASSERTION_AGE_CAP_MINUTES * 60;

    $this->withSession(consoleSessionState($actor, cappedNow()->getTimestamp() - ($capSeconds - 1)));
    $this->getJson('/console-guarded')->assertOk();

    $this->withSession(consoleSessionState($actor, cappedNow()->getTimestamp() - $capSeconds));
    $this->getJson('/console-guarded')->assertStatus(401);

    $this->travelBack();
});

// ─── The cap invalidates the session server-side ────────────────────────────

it('invalidates the session server-side when the assertion-age cap is past', function (): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $response = $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::AssertionAgeCap->value);

    // The session STATE is gone, not merely refused: the issued-at
    // marker, this session's claims, and the guard's own login key are
    // all flushed, and the guard no longer answers for anybody.
    $response->assertSessionMissing(ConsoleSession::ASSERTION_ISSUED_AT);
    $response->assertSessionMissing(ConsoleSession::ROLE);
    $response->assertSessionMissing(consoleGuardSessionKey());

    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse();
});

// ─── The cap is enforced at the GUARD, not by the middleware ────────────────

it('refuses and destroys a capped session on a route carrying no console middleware', function (): void {
    $user = cappedUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $response = $this->getJson('/console-ungated')
        ->assertOk()
        ->assertJsonPath('delegated', false)
        // The chrome must never render a stale delegated attribution.
        ->assertJsonPath('attribution', null);

    // The session did not merely go unread: the guard destroyed it,
    // on a route that never mentioned the Console.
    $response->assertSessionMissing(ConsoleSession::ASSERTION_ISSUED_AT);
    $response->assertSessionMissing(consoleGuardSessionKey());
});

it('does not let a capped session survive by sliding on ungated routes', function (): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    // Activity on a route with no console middleware: under a
    // middleware-only cap this would renew the session indefinitely.
    $this->getJson('/console-ungated')->assertOk();

    // Nothing was renewed — the delegated session is gone, and the
    // console route now sees no delegated session at all.
    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::NotAuthenticated->value);

    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse();
});

it('ends a co-resident local session too, because the whole session is invalidated', function (): void {
    $user = cappedUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession([
        ...consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()),
        'unrelated_state' => 'still-here',
    ]);

    $this->getJson('/console-guarded')->assertStatus(401);

    expect(session()->has('unrelated_state'))->toBeFalse();
});

// ─── Fail closed on every unreadable marker ─────────────────────────────────

it('treats a missing issued-at marker as expired and invalidates', function (): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, consoleAbsent()));

    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('reason', ConsoleReentryReason::SessionInvalidated->value)
        ->assertSessionMissing(consoleGuardSessionKey());

    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse();
});

it('treats an unparseable issued-at marker as expired and invalidates', function (string $marker): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, $marker));

    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::SessionInvalidated->value)
        ->assertSessionMissing(consoleGuardSessionKey());
})->with(['not-a-timestamp', '', '12.5', '1e9', ' 1700000000']);

it('treats a future-dated issued-at marker as expired and invalidates', function (): void {
    $actor = consoleActor();

    // Beyond the configured clock skew: a marker further ahead than the
    // issuer's clock could honestly be would otherwise postpone the cap
    // by exactly that distance.
    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->addMinutes(30)->getTimestamp()));

    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::SessionInvalidated->value)
        ->assertSessionMissing(consoleGuardSessionKey());
});

it('sits exactly on the clock-skew boundary: the configured skew is tolerated, one second past it is not', function (): void {
    $this->travelTo(cappedNow());

    $skew = (int) config('built-for-cloud.console.clock_skew_seconds');

    expect($skew)->toBe(5);

    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, cappedNow()->getTimestamp() + $skew));
    $this->getJson('/console-guarded')->assertOk();

    $this->withSession(consoleSessionState($actor, cappedNow()->getTimestamp() + $skew + 1));
    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::SessionInvalidated->value);

    $this->travelBack();
});

it('kills an orphaned marker whose principal no longer resolves', function (): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor));

    $actor->forceFill(['deactivated_at' => now()])->save();

    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reason', ConsoleReentryReason::SessionInvalidated->value)
        ->assertSessionMissing(ConsoleSession::ASSERTION_ISSUED_AT);
});

it('answers not_authenticated when there is no delegated session at all', function (): void {
    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('reason', ConsoleReentryReason::NotAuthenticated->value);
});

// ─── The structured 401, field by field ─────────────────────────────────────

it('answers a capped request with the whole structured 401, over every transport alike', function (): void {
    // The uniform-401 IS the design (D7's full-page redirect needs PR4's
    // enter endpoint and D13's signed state), so this test asserts the
    // payload rather than pretending the middleware branches on request
    // shape. It does not.
    config(['built-for-cloud.console.reentry_url' => 'https://scalpels.test/console/enter']);

    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $expected = [
        'version' => 1,
        'error' => 'console_reentry_required',
        'reason' => 'assertion_age_cap',
        'reentry_url' => 'https://scalpels.test/console/enter',
        'return_to' => '/admin/orders?page=2',
    ];

    $xhr = $this->postJson('/livewire/update', ['return_to' => '/admin/orders?page=2'], [
        'X-Requested-With' => 'XMLHttpRequest',
    ]);

    $xhr->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertExactJson($expected);

    expect(ConsoleReentryReason::values())->toContain($xhr->json('reason'));

    // The same body, with no XHR markers anywhere on the request. The
    // guards are forgotten first because the auth manager caches guard
    // instances for the life of the application, and a real second
    // request gets a fresh container rather than one that remembers
    // having logged this session out.
    Auth::forgetGuards();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $this->post('/livewire/update', ['return_to' => '/admin/orders?page=2'], ['Accept' => 'text/html'])
        ->assertStatus(401)
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertExactJson($expected);
});

// ─── An unset reentry_url is omitted, never fabricated ──────────────────────

it('emits reentry_url when configured and omits it entirely when not', function (mixed $configured): void {
    $actor = consoleActor();
    $capped = CarbonImmutable::now()->subMinutes(121)->getTimestamp();

    // The positive case, in the SAME test: without it "omitted" is
    // satisfied by an implementation that never emits the field at all.
    config(['built-for-cloud.console.reentry_url' => 'https://scalpels.test/console/enter']);

    $this->withSession(consoleSessionState($actor, $capped));

    $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonPath('reentry_url', 'https://scalpels.test/console/enter');

    config(['built-for-cloud.console.reentry_url' => $configured]);

    Auth::forgetGuards();

    $this->withSession(consoleSessionState($actor, $capped));

    $response = $this->getJson('/console-guarded')
        ->assertStatus(401)
        ->assertJsonMissingPath('reentry_url')
        ->assertJsonPath('reason', 'assertion_age_cap');

    expect(array_keys((array) $response->json()))->not->toContain('reentry_url');
})->with([
    'unset' => [null],
    'empty' => [''],
    'relative' => ['/console/enter'],
    'scheme-less' => ['scalpels.test/console/enter'],
    'no host' => ['https:///console/enter'],
    'not a url' => ['javascript:alert(1)'],
]);

// ─── return_to is relative in every decoded form ────────────────────────────

it('never echoes a non-relative return_to into the 401 body', function (string $hostile): void {
    $actor = consoleActor();

    $this->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $response = $this->postJson('/livewire/update', ['return_to' => $hostile]);

    $response->assertStatus(401);

    expect($response->json('return_to'))->not->toBe($hostile)
        ->and($response->json('return_to'))->toBe('/livewire/update');
})->with([
    'absolute https' => ['https://evil.example/steal'],
    'absolute http' => ['http://evil.example/steal'],
    'protocol relative' => ['//evil.example/steal'],
    'backslash host' => ['/\\evil.example/steal'],
    'double backslash' => ['\\\\evil.example\\steal'],
    'javascript scheme' => ['javascript:alert(1)'],
    'data scheme' => ['data:text/html,<script>alert(1)</script>'],
    'header split' => ["/ok\r\nX-Injected: 1"],
    'bare relative' => ['admin/orders'],
    'encoded double slash' => ['/%2f%2fevil.example/steal'],
    'encoded double slash upper' => ['/%2F%2Fevil.example/steal'],
    'encoded backslash' => ['/%5cevil.example/steal'],
    'encoded backslash upper' => ['/%5Cevil.example/steal'],
    'double encoded double slash' => ['/%252f%252fevil.example/steal'],
    'double encoded backslash' => ['/%255cevil.example/steal'],
    'encoded crlf' => ['/ok%0d%0aX-Injected:%201'],
    'encoded tab' => ['/ok%09then'],
    'encoded null' => ['/ok%00'],
    'encoded space' => ['/ok%20then'],
]);

it('validates return_to as relative in every decoded form, exactly and without cleaning it up', function (): void {
    expect(ConsoleReturnTo::relative('/admin/orders?page=2#top'))->toBe('/admin/orders?page=2#top')
        ->and(ConsoleReturnTo::relative('/'))->toBe('/')
        ->and(ConsoleReturnTo::relative('//evil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('/\\evil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('https://evil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('/%2f%2fevil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('/%252f%252fevil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('/%25252f%25252fevil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative('/%5cevil.example'))->toBeNull()
        ->and(ConsoleReturnTo::relative(''))->toBeNull()
        ->and(ConsoleReturnTo::relative(null))->toBeNull()
        ->and(ConsoleReturnTo::relative(['/ok']))->toBeNull()
        ->and(ConsoleReturnTo::relative("/ok\tthen"))->toBeNull()
        ->and(ConsoleReturnTo::firstRelative(['https://evil.example', '//evil.example']))->toBe('/')
        ->and(ConsoleReturnTo::firstRelative(['https://evil.example', '/second']))->toBe('/second');
});

it('sits exactly on the return_to length boundary', function (): void {
    $atBound = '/'.str_repeat('a', ConsoleReturnTo::MAX_LENGTH - 1);
    $overBound = '/'.str_repeat('a', ConsoleReturnTo::MAX_LENGTH);

    expect(strlen($atBound))->toBe(ConsoleReturnTo::MAX_LENGTH)
        ->and(strlen($overBound))->toBe(ConsoleReturnTo::MAX_LENGTH + 1)
        ->and(ConsoleReturnTo::relative($atBound))->toBe($atBound)
        ->and(ConsoleReturnTo::relative($overBound))->toBeNull();
});

// ─── The clock is the one that decides ──────────────────────────────────────

it('pins the absolute cap at two hours', function (): void {
    expect(ConsoleSessionClock::ASSERTION_AGE_CAP_MINUTES)->toBe(120);
});
