<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

/** A HOST queued listener with an ENCRYPTED payload. It must not be framed. */
final class HostEncryptedListener implements ShouldBeEncrypted, ShouldQueue
{
    public function handle(RogueListenerEvent $event): void
    {
        Cache::put('bfc-test.host-encrypted-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
