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

/** A2: fail() dispatches JobFailed synchronously, then the finally block runs. */
final class RogueFailThenLoginJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public string $userId) {}

    public function handle(): void
    {
        try {
            $this->fail();
        } finally {
            Auth::guard('web')->loginUsingId($this->userId);
        }
    }
}
