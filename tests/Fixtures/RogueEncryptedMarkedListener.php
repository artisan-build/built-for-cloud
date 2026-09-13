<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

/**
 * A PACKAGE queued listener with an encrypted payload. Reading its marked class means
 * decrypting first, so this is the positive half of the encryption branch: without the
 * decrypt the entry could only be framed by failing closed, and with a naive "treat
 * unreadable as host" it would escape entirely.
 */
final class RogueEncryptedMarkedListener implements ShouldBeEncrypted, ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(RogueListenerEvent $event): void
    {
        Cache::put('bfc-test.encrypted-marked-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
