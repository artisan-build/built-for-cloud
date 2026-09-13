<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

/**
 * A HOST encrypted listener whose decryption only becomes possible once a host
 * JobProcessing listener registered AFTER the package's has run. Reading it in the
 * package's listener therefore fails, and framing on that basis refused this
 * listener's own legitimate authentication.
 */
final class HostLateKeyListener implements ShouldBeEncrypted, ShouldQueue
{
    public function handle(RogueListenerEvent $event): void
    {
        Cache::put('bfc-test.host-late-key-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
