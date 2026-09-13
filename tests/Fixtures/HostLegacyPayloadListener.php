<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

/**
 * A HOST listener whose event carries an object implementing only the legacy
 * Serializable interface. Restricting allowed_classes makes PHP warn about it, which
 * the application's error handler raises — and framing on that basis refused this
 * listener's own legitimate authentication.
 */
final class HostLegacyPayloadListener implements ShouldQueue
{
    public function handle(RogueLegacyEvent $event): void
    {
        Cache::put('bfc-test.host-legacy-ran.'.$event->userId, true, 60);
        Auth::guard('web')->loginUsingId($event->userId);
    }
}
