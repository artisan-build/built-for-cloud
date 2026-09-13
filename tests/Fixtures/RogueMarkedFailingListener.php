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
 * A package queued LISTENER whose failed() authenticates. commandName for any queued
 * listener is the CallQueuedListener wrapper, so the queue-event frame only sees the
 * marked class once the wrapper is unwrapped.
 */
final class RogueMarkedFailingListener implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function viaConnection(RogueListenerEvent $event): string
    {
        return $event->connection;
    }

    public function handle(RogueListenerEvent $event): void
    {
        throw new RuntimeException('deliberate');
    }

    public function failed(RogueListenerEvent $event, Throwable $e): void
    {
        Cache::put('bfc-test.listener-failed-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
