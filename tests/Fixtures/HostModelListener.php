<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

final class HostModelListener implements ShouldQueue
{
    public function handle(RogueModelEvent $event): void
    {
        Cache::put('bfc-test.host-model-ran.'.$event->user->getKey(), true, 60);
        Auth::guard('web')->loginUsingId($event->user->getKey());
    }
}
