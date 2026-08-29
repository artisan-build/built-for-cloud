<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleHandoff;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * REDEMPTION — the one way a verified assertion becomes a delegated
 * session, and the four things that have to happen together for it to be
 * safe. {@see ConsoleHandoff} carries
 * the reasoning; these drive it.
 */

// ─── There is exactly ONE way in ────────────────────────────────────────────

it('redeems an active actor into a live delegated session with its own claims bound', function (): void {
    $actor = consoleRedeem(consoleAssertionFor(onBehalfOf: 'Acme Agency', role: ConsoleRole::Admin));

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
    consoleRedeem(consoleAssertionFor());

    expect(session()->has(consoleGuardSessionKey()))->toBeTrue();

    foreach (ConsoleSession::keys() as $key) {
        expect(session()->exists($key))->toBeTrue();
    }
});

// ─── A deactivated actor cannot be logged in by the handoff API ─────────────

it('refuses to redeem a handoff for a deactivated actor, before anything is logged in', function (): void {
    $actor = consoleActor(displayName: 'Jane Original');
    $actor->deactivate();

    expect(fn (): DelegatedActor => consoleRedeem(consoleAssertionFor(displayName: 'Jane Attempting')))
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

it('refuses a deactivated actor at the guard even if something calls login directly', function (): void {
    $actor = consoleActor();
    $actor->deactivate();

    /** @var ConsoleGuard $guard */
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect(fn () => $guard->login($actor->fresh() ?? $actor))
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

    expect(fn (): DelegatedActor => consoleRedeem(consoleAssertionFor()))
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

    expect(fn (): DelegatedActor => consoleRedeem(consoleAssertionFor()))
        ->toThrow(DelegatedActorDeactivated::class);
});

// ─── The Console has to be on, and the guard has to be ours ─────────────────

it('refuses to redeem when the console is not enabled on this deployment', function (): void {
    config(['built-for-cloud.console.enabled' => false]);

    expect(fn (): DelegatedActor => consoleRedeem(consoleAssertionFor()))
        ->toThrow(RuntimeException::class, 'not enabled on this deployment');
});

it('refuses to redeem into a delegated guard the application replaced', function (): void {
    // Redeeming into a guard whose clocks, claims and refusals this
    // package knows nothing about would silently drop D7 and D8.
    config(['auth.guards.'.ConsoleGuardConfiguration::GUARD => ['driver' => 'session', 'provider' => 'users']]);

    auth()->forgetGuards();

    expect(fn (): DelegatedActor => consoleRedeem(consoleAssertionFor()))
        ->toThrow(RuntimeException::class, 'has been replaced by this application');
});
