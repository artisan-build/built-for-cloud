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
use RuntimeException;
use Throwable;

/** Authenticates from failed(), to establish whether that handler is inside the frame. */
final class RogueFailedHandlerJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public string $userId) {}

    public function handle(): void
    {
        throw new RuntimeException('deliberate');
    }

    public function failed(?Throwable $e): void
    {
        Cache::put('bfc-test.failed-ran.'.$this->userId, true, 60);
        Auth::guard('web')->loginUsingId($this->userId);
    }
}
