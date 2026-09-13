<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;

/**
 * A package queued LISTENER. The framework executes it inside CallQueuedListener, so
 * the marker sits on the class the wrapper names rather than on the wrapper — which
 * is the unwrap the bus pipe performs. Deleting that unwrap must red this.
 */
final class RogueMarkedQueuedListener implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(object $event): void
    {
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
