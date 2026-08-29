<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleHandoff;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/console-guarded', fn (): array => ['ok' => true]);
});

/**
 * REDEMPTION — the one way a verified assertion becomes a delegated
 * session, and the four things that have to happen together for it to be
 * safe. {@see ConsoleHandoff} carries
 * the reasoning; these drive it.
 */

// ─── There is exactly ONE way in ────────────────────────────────────────────

it('redeems an active actor into a live delegated session with its own claims bound', function (): void {
    $actor = consoleRedeem(onBehalfOf: 'Acme Agency', role: ConsoleRole::Admin);

    /** @var ConsoleGuard $guard */
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard->id())->toBe($actor->getAuthIdentifier())
        ->and($guard->claims()?->attribution())->toBe('Jane Operator (Acme Agency)')
        ->and($guard->claims()?->role)->toBe(ConsoleRole::Admin)
        // The assertion's own iat is what the cap will be measured from,
        // and it is written once — never refreshed.
        ->and(session()->get(ConsoleSession::ASSERTION_ISSUED_AT))->toBeInt();
});

it('writes the session state and the login together, so neither can exist without the other', function (): void {
    consoleRedeem();

    expect(session()->has(consoleGuardSessionKey()))->toBeTrue();

    foreach (ConsoleSession::keys() as $key) {
        expect(session()->exists($key))->toBeTrue();
    }
});

// ─── A deactivated actor cannot be logged in by the handoff API ─────────────

it('refuses to redeem a handoff for a deactivated actor, before anything is logged in', function (): void {
    $actor = consoleActor(displayName: 'Jane Original');
    $actor->deactivate();

    expect(fn (): DelegatedActor => consoleRedeem(displayName: 'Jane Attempting'))
        ->toThrow(DelegatedActorDeactivated::class);

    // Nothing was logged in — not even for the redemption request.
    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse()
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(session()->exists(ConsoleSession::ASSERTION_ISSUED_AT))->toBeFalse();

    // ...and the attempt WAS recorded, with the claims it arrived
    // carrying, because the record is committed BEFORE the decision that
    // refuses it. One transaction would have rolled this back.
    expect($actor->fresh()?->last_handoff_display_name)->toBe('Jane Attempting');
});

// ─── AC30: nothing mints a session from an unverified assertion ─────────────

it('exposes no way to log a delegated actor in without signed bytes', function (string $method): void {
    // The previous revision had a PUBLIC login(DelegatedActor). Combined
    // with Assertion::fromVerifiedClaims() — public, and documented as
    // NOT being proof of provenance — consuming code could assemble an
    // assertion carrying role=admin and get a delegated admin session
    // with no signature ever checked. Those seams are gone: the only
    // operation that creates a principal takes the token.
    expect(method_exists(consoleGuard(), $method))->toBeFalse();
})->with(['login', 'attempt', 'once', 'loginUsingId', 'onceUsingId', 'viaRemember', 'basic']);

it('has no class left that redeems an assertion object', function (): void {
    // ConsoleHandoff::redeem(Assertion) was the other half of the same
    // hole. It does not exist; there is no second choke point to keep in
    // step with this one.
    expect(class_exists('ArtisanBuild\\BuiltForCloud\\Console\\ConsoleHandoff'))->toBeFalse();
});

it('refuses a token whose signature does not verify, writing nothing', function (): void {
    $token = consoleSignedAssertion();

    expect(fn (): DelegatedActor => consoleGuard()->redeem(consoleTamperSignature($token)))
        ->toThrow(AssertionRefused::class);

    expect(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(ConsoleSession::hasState(app(Session::class)))->toBeFalse()
        // Not even a handoff row: verification comes before any read or
        // write, so a token that does not verify leaves no trace at all.
        ->and(DelegatedActor::query()->count())->toBe(0);
});

it('refuses a token whose claims were rewritten to claim the admin role', function (): void {
    // The exact escalation the object-taking API allowed, now attempted
    // the only way that is left: over the wire, against the signature.
    $token = consoleSignedAssertion(role: ConsoleRole::Member);

    expect(fn (): DelegatedActor => consoleGuard()->redeem(
        consoleTamperClaims($token, '"role":"member"', '"role":"admin"'),
    ))->toThrow(AssertionRefused::class);

    expect(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(DelegatedActor::query()->count())->toBe(0);
});

it('refuses garbage and empty input rather than treating it as a claim set', function (string $token): void {
    expect(fn (): DelegatedActor => consoleGuard()->redeem($token))
        ->toThrow(AssertionRefused::class);

    expect(session()->has(consoleGuardSessionKey()))->toBeFalse();
})->with(['', 'not-a-token', 'v4.public.', 'v2.local.abcdef']);

it('cannot be given a delegated principal through setUser, which is the one public seam left', function (): void {
    // setUser() is on the Guard contract and is what Laravel's actingAs()
    // calls, so it stays public. It is BOUNDED rather than trusted: it
    // writes nothing to the session, so the principal still has to
    // survive actor() — which independently demands session-bound claims
    // and a clock inside the cap — and the next request has nothing to
    // rehydrate. This is a CALLER-ENFORCED seam only in the sense that a
    // caller may set an in-memory principal; it cannot mint a session.
    $actor = consoleActor();

    $guard = consoleGuard();
    $guard->setUser($actor);

    expect($guard->actor())->toBeNull()
        ->and($guard->check())->toBeFalse()
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(ConsoleSession::hasState(app(Session::class)))->toBeFalse();
});

it('refuses a deactivated actor inside redeem, before anything is logged in', function (): void {
    $actor = consoleActor();
    $actor->deactivate();

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(DelegatedActorDeactivated::class)
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse();
});

// ─── Deactivation racing a redemption ───────────────────────────────────────

it('refuses a handoff for an actor deactivated between recording it and the locked re-read', function (): void {
    consoleActor();

    // The interleaving a concurrent offboard produces: the deactivation
    // commits AFTER the handoff row is written and BEFORE the login.
    // Driven through a model hook rather than a second process, and it
    // fails on the code path that matters — redemption re-reading the
    // row instead of trusting the model it just wrote.
    $interleaved = false;

    DelegatedActor::saved(function (DelegatedActor $saved) use (&$interleaved): void {
        if ($interleaved) {
            return;
        }

        $interleaved = true;

        DB::table('bfc_delegated_actors')
            ->where('id', $saved->getKey())
            ->update(['deactivated_at' => now()]);
    });

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(DelegatedActorDeactivated::class);

    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse()
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse();
})->note('The row LOCK itself is not proven here: lockForUpdate() compiles to nothing on SQLite, which is what this suite runs. What is proven is that redemption re-reads the row inside the transaction, and that the session write and the login happen inside that same transaction rather than after it — the half a second process would otherwise race past. Debt row bfc-console-redemption-lock.');

it('deactivates through the same locked read redemption uses', function (): void {
    $actor = consoleActor();

    expect($actor->deactivate())->toBeTrue()
        ->and($actor->isActive())->toBeFalse()
        ->and($actor->fresh()?->deactivated_at)->not->toBeNull();

    // Idempotent: one containment is one event, and a second call does
    // not move the timestamp.
    $deactivatedAt = $actor->fresh()?->deactivated_at;

    expect($actor->fresh()?->deactivate())->toBeFalse()
        ->and($actor->fresh()?->deactivated_at?->getTimestamp())->toBe($deactivatedAt?->getTimestamp());

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(DelegatedActorDeactivated::class);
});

// ─── The Console has to be on, and the guard has to be ours ─────────────────
//
// Both of these were runtime checks inside the old ConsoleHandoff, and
// both are now structural: `redeem()` lives ON the guard, so there is
// nothing to redeem into unless this package's guard is what resolves.

// "The Console is not enabled" is not driven here, and deliberately not
// with a skipped test either: the flag gates REGISTRATION at boot, so
// the state cannot be reached by flipping config inside a booted
// console-enabled app. ConsoleDisabledTest boots the whole application
// in that state and asserts `auth('bfc-console')` throws, which is the
// same claim from the only place it is true.

it('has nothing to redeem into when the application replaced the delegated guard', function (): void {
    // Redeeming into a guard whose clocks, claims and refusals this
    // package knows nothing about would silently drop D7 and D8. It
    // cannot happen: `redeem()` is a method on ConsoleGuard, and an app
    // that took the guard name gets its own guard, which has none.
    config(['auth.guards.'.ConsoleGuardConfiguration::GUARD => ['driver' => 'session', 'provider' => 'users']]);

    auth()->forgetGuards();

    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard)->not->toBeInstanceOf(ConsoleGuard::class)
        ->and(method_exists($guard, 'redeem'))->toBeFalse();
});

// ─── AC29: a throwing Login listener must leave no usable session ───────────

it('leaves no usable session when a Login listener throws during redemption', function (): void {
    // The customer-defined listener nobody in this package controls: an
    // audit backend that is down, a webhook that times out.
    Event::listen(Login::class, function (): void {
        throw new RuntimeException('the audit backend is unavailable');
    });

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(RuntimeException::class, 'audit backend');

    // SessionGuard::login() writes the identifier and REGENERATES the
    // session before it dispatches the Login event, so by the time the
    // listener throws the session already carries a delegated identifier
    // and this session's admin claims. The database transaction rolls
    // back; the session does not, and Laravel's routing pipeline turns a
    // throw into a rendered response, which StartSession then saves. So
    // the redemption has to compensate.
    expect(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(ConsoleSession::hasState(app(Session::class)))->toBeFalse();

    // The discriminating half: whatever survived, the next request
    // carrying it is not an authenticated delegated admin.
    $this->withSession(session()->all());

    $this->getJson('/console-guarded')->assertStatus(401);
});

it('compensates on any throwable from the login path, not only on a Login listener', function (): void {
    // Same compensation, reached through a different failure: the
    // Authenticated event SessionGuard::setUser() fires after the
    // session is already written.
    Event::listen(Authenticated::class, function (): void {
        throw new RuntimeException('the attribution sink refused');
    });

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(RuntimeException::class, 'attribution sink');

    expect(session()->has(consoleGuardSessionKey()))->toBeFalse()
        ->and(ConsoleSession::hasState(app(Session::class)))->toBeFalse();
});

it('does not touch a co-resident session when the refusal happens before any session write', function (): void {
    // A contained actor is refused at the locked read, BEFORE anything
    // is written, so the compensation does not run and an unrelated
    // local session in the same browser survives. Compensation is for
    // damage actually done, not a blanket flush.
    $actor = consoleActor();
    $actor->deactivate();

    session()->put('unrelated_state', 'still-here');

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(DelegatedActorDeactivated::class);

    expect(session()->get('unrelated_state'))->toBe('still-here')
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse();
});
