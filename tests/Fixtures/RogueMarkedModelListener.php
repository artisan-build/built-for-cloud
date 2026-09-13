<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

final class RogueMarkedModelListener implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(RogueModelEvent $event): void
    {
        Cache::put('bfc-test.marked-model-ran.'.$event->user->getKey(), true, 60);
        Auth::guard('web')->loginUsingId($event->user->getKey());
    }
}
