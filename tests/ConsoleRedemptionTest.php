<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RecordingExceptionHandler;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ThrowingSessionHandler;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/console-guarded', fn (): array => ['ok' => true]);
});

/**
 * REDEMPTION — the one operation that turns signed assertion bytes into
 * a delegated session, and the things that have to happen together for
 * it to be safe. {@see ConsoleGuard::redeem()} carries the reasoning;
 * these drive it.
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

// ─── The compensation must never become the failure the caller sees ─────────

it('surfaces the original failure, not the compensation failure, when the session store is unreachable', function (): void {
    // The scenario: a host listener rejects the entry AND the session
    // store is down, so the compensation that would destroy the session
    // throws as well. An uncaught throw there would REPLACE the original
    // — the caller would be told the session store is unreachable when
    // what actually happened is that their audit backend refused the
    // entry — and the wrong cause is the one that gets investigated.
    ThrowingSessionHandler::reset();
    RecordingExceptionHandler::reset();

    app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

    // A session store whose destroy() can be armed to fail, captured by
    // the guard when it is rebuilt below.
    app()->instance('session.store', new Store('bfc-compensation-test', new ThrowingSessionHandler));
    Auth::forgetGuards();

    // The store fails only from inside the Login listener onward, so the
    // redemption's own session write and regeneration succeed and the
    // ONLY thing left to fail is the compensation.
    Event::listen(Login::class, function (): void {
        ThrowingSessionHandler::$failOnDestroy = true;

        throw new RuntimeException('the audit backend is unavailable');
    });

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(RuntimeException::class, 'audit backend');

    // ...and the compensation failure was not silently dropped either:
    // it went to the application's exception handler.
    expect(RecordingExceptionHandler::$reported)->toHaveCount(1)
        ->and(RecordingExceptionHandler::$reported[0]->getMessage())->toBe('the session store is unreachable');

    // What still holds when that path is taken: Session::invalidate() is
    // flush() — in memory, cannot fail — followed by the migrate() whose
    // handler I/O did fail, so the delegated identity is gone from the
    // session even though the store could not be told.
    expect(app(Session::class)->all())->toBe([]);

    ThrowingSessionHandler::reset();
});

it('reports nothing and swallows nothing when the compensation succeeds', function (): void {
    // The ordinary failure, so "reported once" above cannot pass for the
    // wrong reason — a compensation that always reported would look
    // identical on that assertion alone.
    RecordingExceptionHandler::reset();

    app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

    Event::listen(Login::class, function (): void {
        throw new RuntimeException('the audit backend is unavailable');
    });

    expect(fn (): DelegatedActor => consoleRedeem())
        ->toThrow(RuntimeException::class, 'audit backend');

    expect(RecordingExceptionHandler::$reported)->toBe([])
        ->and(session()->has(consoleGuardSessionKey()))->toBeFalse();
});

// ─── The session-building seams ─────────────────────────────────────────────

it('offers no public way to write a delegated session\'s claims', function (): void {
    // ConsoleSession used to carry a public static begin(Assertion),
    // which meant the package handed out a way to assemble a delegated
    // session's claims from an assertion nothing had verified — next
    // door to a redeem() built precisely so that could not happen. The
    // write now lives inside the guard, private, behind verification.
    expect(method_exists(ConsoleSession::class, 'begin'))->toBeFalse();

    $writers = array_filter(
        get_class_methods(ConsoleSession::class),
        static fn (string $method): bool => ! in_array($method, ['claims', 'hasState', 'keys'], true),
    );

    expect($writers)->toBe([]);
});

it('does not authenticate a principal handed to setUser, even alongside hand-written claims', function (): void {
    // THE ORDERING THIS PINS. setUser() is public because the Guard
    // contract requires it, and SessionGuard::user() returns whatever it
    // was given WITHOUT consulting the session. So a caller that set a
    // delegated actor and then wrote the four claim keys would, without
    // the guard's session cross-check, have an authenticated delegated
    // admin for the request — with no signature anywhere.
    $actor = consoleActor(role: ConsoleRole::Admin);

    $guard = consoleGuard();

    // Everything a redemption writes EXCEPT the guard's own login key,
    // which is the one thing only a real login produces.
    session()->put(ConsoleSession::ASSERTION_ISSUED_AT, now()->getTimestamp());
    session()->put(ConsoleSession::DISPLAY_NAME, 'Jane Forged');
    session()->put(ConsoleSession::ROLE, ConsoleRole::Admin->value);
    session()->put(ConsoleSession::ON_BEHALF_OF, null);

    $guard->setUser($actor);

    expect($guard->actor())->toBeNull()
        ->and($guard->check())->toBeFalse()
        ->and($guard->id())->toBeNull();

    // THE POSITIVE CONTROL, in the same test, so the refusal above
    // cannot pass because the claims or the clock were wrong: add the
    // one thing only a login writes — the guard's own session key — and
    // the very same principal resolves. The cross-check is what said no.
    //
    // It also pins the RESIDUE exactly. Anything that can write the
    // session store can write these five keys, and the result is
    // indistinguishable from a redeemed session. That is irreducible —
    // it is what this suite's own consoleSessionState() does to reach
    // states a real redemption cannot produce — and it is not a
    // credential or login path, which is what §4.3 is about. The claim
    // held is narrower and exact: no package API assembles a delegated
    // session without verified assertion bytes.
    // (The refusal above also destroyed the session, which is why the
    // control re-seeds all five keys rather than adding one to what is
    // left.)
    foreach (consoleSessionState($actor) as $key => $value) {
        session()->put($key, $value);
    }

    Auth::forgetGuards();

    expect(consoleGuard()->actor()?->getKey())->toBe($actor->getKey());
});

it('refuses a principal whose identifier is not the one this session names', function (): void {
    // The same cross-check from the other side: a live, valid session
    // for actor A, with actor B handed to setUser. B must not act.
    $first = consoleActor(subject: 'operator_a', displayName: 'Operator A');
    $second = consoleActor(subject: 'operator_b', displayName: 'Operator B');

    $guard = consoleGuard();

    foreach (consoleSessionState($first) as $key => $value) {
        session()->put($key, $value);
    }

    expect($guard->actor()?->getKey())->toBe($first->getKey());

    // Same request, same guard: something hands it a DIFFERENT actor.
    // The session still names A, so B does not act — and neither does A,
    // because the session is invalidated on the refusal.
    $guard->setUser($second);

    expect($guard->actor())->toBeNull()
        ->and($guard->check())->toBeFalse();
});
