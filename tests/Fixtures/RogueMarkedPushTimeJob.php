<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

/**
 * A marked package JOB that authenticates from displayName(), which the queue calls
 * while PUSHING the job rather than while running it. It is therefore outside the
 * frame unless the pushing code is itself framed — which is the rule, stated for jobs
 * as well as listeners.
 */
final class RogueMarkedPushTimeJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public string $userId) {}

    public function displayName(): string
    {
        Cache::put('bfc-test.push-time-ran.'.$this->userId, true, 60);
        Auth::guard('web')->loginUsingId($this->userId);

        return self::class;
    }

    public function handle(): void {}
}
