<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\Audit\ConsoleAction;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SinkAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Support\Facades\DB;
use LogicException;

// Deliberately NOT RefreshDatabase: that trait wraps every test in a
// transaction, which would make transactionLevel() lie about the case
// under test.

it('refuses to record a lifecycle event outside a database transaction', function (): void {
    expect(DB::transactionLevel())->toBe(0);

    expect(fn (): mixed => app(LifecycleEventRecorder::class)->record(LifecycleEventType::Issued))
        ->toThrow(LogicException::class, 'transaction');
});

it('refuses to record an app action outside a database transaction', function (): void {
    // The app-action stream takes the same ruling as the lifecycle one:
    // an event written outside the action's transaction is a record that
    // can outlive the thing it records. It throws rather than opening a
    // transaction of its own, because one this class opened would commit
    // independently of the caller's — which is the failure the
    // requirement exists to prevent.
    expect(DB::transactionLevel())->toBe(0);

    expect(fn (): mixed => app(AppActionRecorder::class)->record(
        action: ConsoleAction::ConsoleEntered,
        actor: AppActionActor::localUser((new User)->forceFill(['id' => 7])),
        reason: AppActionReason::ConsoleEntry,
    ))->toThrow(LogicException::class, 'transaction');
});

it('refuses a direct model write made outside a transaction', function (): void {
    // AC10 at the ROW, not only at the recorder — this is the half that
    // holds for an app writing the model directly. It lives in THIS file
    // because RefreshDatabase wraps every test it touches in a
    // transaction, which would make transactionLevel() lie about the
    // case under test.
    expect(DB::transactionLevel())->toBe(0);

    expect(fn (): mixed => AppActionEvent::query()->create([
        'action' => SinkAppAction::InvoiceVoided->value,
        'action_vocabulary' => SinkAppAction::class,
        'reason' => AppActionReason::Requested->value,
        'actor_type' => AppActorType::DelegatedActor->value,
        'actor_ref' => DelegatedActor::IDENTIFIER_PREFIX.'7',
        'occurred_at' => now(),
    ]))->toThrow(LogicException::class, 'transaction');

    // No "and nothing was stored" assertion follows, deliberately: this
    // file runs without RefreshDatabase — which is the whole reason the
    // case is reachable here — so the table does not exist to read. The
    // refusal happening BEFORE any SQL is the property, and a read that
    // could only ever fail would be a check dressed up as one.
});

it('leaves no event behind when an emission outside a transaction is refused', function (): void {
    // The schema is created in-situ for THIS test alone, so the refusal
    // can be checked against what it actually left behind and not only
    // against the exception it throws. (The tests above run without a
    // schema on purpose, and a shared beforeEach would change the ground
    // they were written on.) Testbench rebuilds the in-memory database
    // per test, so the migration leaves nothing behind for the next one.
    $this->artisan('migrate');

    expect(DB::transactionLevel())->toBe(0);

    expect(fn (): mixed => app(AppActionRecorder::class)->record(
        action: ConsoleAction::ConsoleEntered,
        actor: AppActionActor::localUser((new User)->forceFill(['id' => 7])),
        reason: AppActionReason::ConsoleEntry,
    ))->toThrow(LogicException::class, 'transaction');

    // The refusal happens BEFORE the savepoint exists and before any SQL
    // runs, so nothing can have been written — asserted, not assumed,
    // because a recorder that "helpfully" opened a transaction of its
    // own would commit an event no action ever performed, and on a
    // migrated database that commit would be invisible to the tests
    // above.
    expect(AppActionEvent::query()->count())->toBe(0)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0);
});
