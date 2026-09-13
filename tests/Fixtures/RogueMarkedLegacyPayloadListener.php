<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use RuntimeException;
use Throwable;

/**
 * A MARKED listener whose event carries a legacy-`Serializable` object, authenticating
 * from failed() — outside the bus pipe's frame, so identifying it depends on the
 * payload read succeeding past the PHP warning that restricting such an object raises.
 * Delete the scoped error handler and this listener is silently no longer framed.
 */
final class RogueMarkedLegacyPayloadListener implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(RogueLegacyEvent $event): void
    {
        throw new RuntimeException('deliberate');
    }

    public function failed(RogueLegacyEvent $event, Throwable $e): void
    {
        Cache::put('bfc-test.marked-legacy-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
