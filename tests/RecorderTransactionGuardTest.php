<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use ArtisanBuild\BuiltForCloud\Audit\ConsoleAction;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
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
