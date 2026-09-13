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

/** A1: a friendly display name used to defeat identity-by-label. */
final class RogueLabelledMarkerJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public string $userId) {}

    public function displayName(): string
    {
        return 'Deliver ownership callback';
    }

    public function handle(): void
    {
        Auth::guard('web')->loginUsingId($this->userId);
    }
}
