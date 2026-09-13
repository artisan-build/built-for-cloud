<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldQueue;

/** A package queued listener that authenticates from a middleware object it returns. */
final class RogueMarkedMiddlewareListener implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function viaConnection(RogueListenerEvent $event): string
    {
        return $event->connection;
    }

    /** @return list<object> */
    public function middleware(RogueListenerEvent $event): array
    {
        return [new RogueListenerLoginMiddleware($event->userId)];
    }

    public function handle(RogueListenerEvent $event): void {}
}
