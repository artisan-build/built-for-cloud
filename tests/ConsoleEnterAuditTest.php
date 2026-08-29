<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\Audit\ConsoleAction;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use Illuminate\Auth\Events\Login;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * The named gap PR7 closes: `POST /bfc/console/enter` audited nothing on
 * a SUCCESSFUL entry, while D4's whole promise is that an app's audit
 * trail reads "Jane (Acme Agency) via Scalpels".
 *
 * Every test here drives the REAL route. Nothing calls the recorder
 * directly, because what is being pinned is that the DOOR emits, in the
 * door's own transaction.
 */
beforeEach(function (): void {
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/entered-landing', fn (): array => ['ok' => true]);
});

function enterTheDoor(array $handoff): TestResponse
{
    return test()->post('/bfc/console/enter', $handoff);
}

// ─── AC12: one event, inside the entry's own transaction ────────────────────

it('records one app-action event for a successful entry, through the real door', function (): void {
    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);

    $actor = DelegatedActor::query()->sole();
    $event = AppActionEvent::query()->sole();

    expect($event->action)->toBe(ConsoleAction::ConsoleEntered->value)
        ->and($event->action_vocabulary)->toBe(ConsoleAction::class)
        ->and($event->reason)->toBe(AppActionReason::ConsoleEntry)
        // Typed as the delegated actor that was ADMITTED, by its
        // type-qualified identity — never the bare key.
        ->and($event->actor_type)->toBe(AppActorType::DelegatedActor)
        ->and($event->actor_ref)->toBe(DelegatedActor::IDENTIFIER_PREFIX.$actor->getKey())
        ->and($event->id)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/');

    expect(AppActionOutboxEntry::query()->sole()->event_id)->toBe($event->id);
});

it('keys a successful entry\'s ledger row to the mint, so dropping the key falls back to the event id', function (): void {
    // THE PIN THAT WAS WEAKENED, restored. A round-1 revision asserted
    // the stored key equalled a prefix plus the mint hash; a later one
    // relaxed it to "is 64 hex" and "is not the raw mint hash", which
    // cannot fail: `AppActionRecorder` defaults the natural key to the
    // EVENT ID, so deleting `naturalKey:` from ConsoleEnter still yields
    // a 64-hex digest that is still not the mint hash, and the whole
    // suite stayed green while "one mint, at most one entry event" went
    // unpinned.
    //
    // Recomputed from the MINT — an input this test derives
    // independently of the door — through the recorder's own function,
    // so the algorithm is pinned rather than restated. Dropping the
    // argument reds this.
    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);

    $mintHash = AssertionBurn::query()->sole()->mint_hash;
    $ledger = AppActionOutboxEntry::query()->sole();

    expect($ledger->dedup_key)
        ->toBe(AppActionRecorder::dedupKeyFor(ConsoleAction::ConsoleEntered, $mintHash));

    // …and the fallback really is a different value, so the assertion
    // above is discriminating rather than accidentally satisfied.
    expect(AppActionRecorder::dedupKeyFor(ConsoleAction::ConsoleEntered, AppActionEvent::query()->sole()->id))
        ->not->toBe($ledger->dedup_key);

    // The stored key is still a digest and never the mint hash itself.
    expect($ledger->dedup_key)->toMatch('/^[0-9a-f]{64}$/')->not->toBe($mintHash);
});

it('records the agency the entering handoff named, and null when it named none', function (): void {
    // D4's line, from the handoff's OWN claims — not from the actor
    // row, which a later handoff for the same subject would rewrite.
    enterTheDoor(consoleHandoff('/orders', ['on_behalf_of' => 'Acme Agency']))->assertStatus(303);

    expect(AppActionEvent::query()->sole()->on_behalf_of)->toBe('Acme Agency');

    // A direct operator — same subject, a later mint carrying no agency
    // — records none rather than inheriting the earlier one.
    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);

    expect(AppActionEvent::query()->orderByDesc('created_at')->get()->pluck('on_behalf_of')->sort()->values()->all())
        ->toBe([null, 'Acme Agency']);
});

it('records one event per entry, so two entries by the same operator are two events', function (): void {
    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);
    enterTheDoor(consoleHandoff('/reports'))->assertStatus(303);

    expect(AppActionEvent::query()->count())->toBe(2)
        ->and(AppActionEvent::query()->distinct()->count('id'))->toBe(2)
        // Two mints, two dedup keys: keying on the SESSION would have
        // collapsed these into one recorded entry.
        ->and(AppActionOutboxEntry::query()->distinct()->count('dedup_key'))->toBe(2);
});

// ─── AC13: an entry that rolls back is not recorded ─────────────────────────

it('records no entry event when the entry transaction rolls back', function (): void {
    // The same forced failure ConsoleEnterTest uses for the burn: a host
    // listener on `Login` that throws, inside the transaction that holds
    // the burn, the redemption and now the event.
    Event::listen(Login::class, function (): never {
        throw new RuntimeException('an audit backend that is down');
    });

    $handoff = consoleHandoff('/orders');

    enterTheDoor($handoff)->assertStatus(500);

    // The entry that did not happen is not recorded — and neither is the
    // burn, which is how we know the rollback genuinely happened rather
    // than the emission simply never being reached.
    expect(AppActionEvent::query()->count())->toBe(0)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0)
        ->and(AssertionBurn::query()->count())->toBe(0);

    // And the same assertion, once it can succeed, records exactly one.
    Event::forget(Login::class);

    enterTheDoor($handoff)->assertStatus(303);

    expect(AppActionEvent::query()->count())->toBe(1);
});

it('does not serve an entry it could not record', function (): void {
    // The success side of the fail-closed ruling the refusal path
    // already carries. The outage is driven for real: the app-action
    // outbox is gone, so the recorder's second insert throws and takes
    // the burn and the redemption with it.
    Schema::drop('bfc_app_action_outbox');

    $failed = enterTheDoor(consoleHandoff('/orders'));

    $failed->assertStatus(500);

    expect(AppActionEvent::query()->count())->toBe(0)
        ->and(AssertionBurn::query()->count())->toBe(0);

    // The session the redemption had begun is not usable either: the
    // door did not quietly admit somebody it failed to record. Driven by
    // replaying the cookie the failed response set, which is the only
    // honest way to ask whether a session survived — reading keys would
    // say nothing about what the browser can do with them.
    $cookie = $failed->getCookie((string) config('session.cookie'));

    expect($cookie)->not->toBeNull();

    $this->withCookie((string) config('session.cookie'), (string) $cookie?->getValue())
        ->getJson('/entered-landing')
        ->assertStatus(401);
});

// ─── AC14: the door is not weakened ─────────────────────────────────────────

it('writes nothing to the credential audit stream on a successful entry', function (): void {
    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);

    // The credential stream is credential-work only. A success adds
    // nothing to it; the refusal rows it already carries are unchanged.
    expect(CredentialAuditEvent::query()->count())->toBe(0)
        ->and(CredentialOutboxEntry::query()->count())->toBe(0)
        ->and(AppActionEvent::query()->count())->toBe(1);
});

it('keeps recording refusals where refusals have always been recorded', function (): void {
    // The refusal stream did not move. A refused entry writes a
    // credential `denied_action` row and NO app-action event: the door
    // records who walked through, not who was turned away — that is
    // still D13's row on the other stream.
    enterTheDoor(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    expect(CredentialAuditEvent::query()->count())->toBe(1)
        ->and(AppActionEvent::query()->count())->toBe(0);
});

it('drains no outbox on the way out of a successful entry', function (): void {
    // THE DRAIN DECISION, driven rather than argued. A refusal leaves a
    // claimable credential outbox row behind on purpose; a successful
    // entry must not deliver it, because a drain is O(claimable rows),
    // may send mail, and this is a page-load path an operator waits on.
    enterTheDoor(consoleHandoff('/orders', ['aud' => 'https://someone-else.test']))
        ->assertStatus(ConsoleEnter::REFUSAL_STATUS);

    $pending = CredentialOutboxEntry::query()->sole();

    expect($pending->delivered_at)->toBeNull()
        ->and($pending->attempts)->toBe(0);

    enterTheDoor(consoleHandoff('/orders'))->assertStatus(303);

    // Still exactly as the refusal left it: untouched, unattempted.
    $stillPending = CredentialOutboxEntry::query()->sole();

    expect($stillPending->delivered_at)->toBeNull()
        ->and($stillPending->attempts)->toBe(0);
});
