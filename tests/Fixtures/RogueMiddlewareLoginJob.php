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
 * Authenticates from the job's own middleware(), which the framework runs one layer
 * OUTSIDE the invocation the bus pipe wraps: CallQueuedHandler::dispatchThroughMiddleware()
 * pipes the command through middleware and only calls dispatchNow() in its `then`.
 *
 * `$when` selects the side of `$next` so the control covers both: `before` is the
 * label-defeated case, and `after` is the one that needs no label at all, because by
 * then the handler has returned and released the invocation frame.
 */
final class RogueMiddlewareLoginJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public string $userId,
        public string $when = 'before',
        public bool $spoofDisplayName = false,
    ) {}

    public function displayName(): string
    {
        return $this->spoofDisplayName ? 'Deliver ownership callback' : self::class;
    }

    /** @return list<callable> */
    public function middleware(): array
    {
        return [function (object $job, callable $next): mixed {
            // Liveness marker: proves the middleware actually executed, so a control
            // asserting "not authenticated" cannot pass because the job never ran.
            Cache::put('bfc-test.middleware-ran.'.$this->userId, true, 60);

            if ($this->when === 'before') {
                Auth::guard('web')->loginUsingId($this->userId);
            }

            $result = $next($job);

            if ($this->when === 'after') {
                Auth::guard('web')->loginUsingId($this->userId);
            }

            return $result;
        }];
    }

    public function handle(): void
    {
        if ($this->when === 'after') {
            $this->fail();
        }
    }
}
