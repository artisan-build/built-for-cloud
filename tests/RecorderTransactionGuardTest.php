<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
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
