<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Closure;
use Illuminate\Events\CallQueuedListener;

/**
 * Opens the system-authority frame around a package queue entry's ACTUAL
 * INVOCATION, the way {@see Commands\SystemAuthorityCommand} already does for
 * commands.
 *
 * The previous wiring observed queue EVENTS instead, and observation was wrong in
 * three ways that were each reproduced by execution: identity came from
 * `$job->resolveName()`, which returns the payload's caller-settable `displayName`;
 * the frame was released on `JobFailed`, which `InteractsWithQueue::fail()`
 * dispatches synchronously while the handler is still running; and
 * `dispatchNow()`/`dispatchSync()` fire no queue events at all, so those routes
 * were never framed.
 *
 * A bus pipe is framed at the invocation instead, which covers every dispatch
 * route by construction: the queue worker reaches it through
 * `CallQueuedHandler::call()` -> `dispatchThroughMiddleware()` ->
 * `Dispatcher::dispatchNow()`, and the synchronous routes call `dispatchNow()`
 * directly. `dispatchNow()` runs the command through these pipes.
 *
 * Identity is taken from the OBJECT, never from a name, display string or summary
 * — every one of those is caller-settable, and taking identity from one is the
 * mistake this class exists to stop repeating.
 */
final readonly class SystemAuthorityBusFrame
{
    public function __construct(private SystemAuthorityContext $context) {}

    public function handle(mixed $command, Closure $next): mixed
    {
        if (! $this->isPackageEntry($command)) {
            return $next($command);
        }

        return $this->context->run(static fn (): mixed => $next($command));
    }

    private function isPackageEntry(mixed $command): bool
    {
        if ($command instanceof SystemAuthorityQueueEntry) {
            return true;
        }

        // A queued listener is executed inside a framework wrapper, so the marker
        // sits on the class the wrapper names rather than on the wrapper.
        if ($command instanceof CallQueuedListener) {
            return is_string($command->class)
                && is_a($command->class, SystemAuthorityQueueEntry::class, true);
        }

        // A queued CLOSURE is deliberately NOT claimed. Origin would have to come
        // from the closure's declaring file, and that does not survive the queue:
        // after a serialise round-trip `ReflectionFunction::getFileName()` returns a
        // synthetic `laravel-serializable-closure://` URI rather than a path, so a
        // package closure is indistinguishable from a host one by the time this pipe
        // sees it. Queued closures are disclosed as outside the bound instead of
        // guessed at, and the package dispatches none.
        return false;
    }
}
