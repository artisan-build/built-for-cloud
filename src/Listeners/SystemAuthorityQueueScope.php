<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;

final class SystemAuthorityQueueScope
{
    /** @var array<int, int> */
    private array $tokens = [];

    public function __construct(private readonly SystemAuthorityContext $context) {}

    public function processing(JobProcessing $event): void
    {
        $class = $this->entryClass($event->job);

        if ($class === null || ! is_a($class, SystemAuthorityQueueEntry::class, true)) {
            return;
        }

        $jobId = spl_object_id($event->job);
        $this->leave($jobId);
        $this->tokens[$jobId] = $this->context->enter();
    }

    /**
     * Released on JobAttempted ONLY.
     *
     * JobProcessed, JobExceptionOccurred and JobFailed all fire while package code
     * may still be running: InteractsWithQueue::fail() dispatches JobFailed
     * synchronously and returns to the handler, and control afterwards unwinds back
     * through the job's own middleware. JobAttempted is dispatched from a `finally`
     * in both Worker::process and SyncQueue::executeJob, so it is the first point at
     * which the entry has genuinely finished. Proven on both routes by executed
     * controls rather than by reading the framework.
     */
    public function finished(JobAttempted $event): void
    {
        $this->leave(spl_object_id($event->job));
    }

    private function leave(int $jobId): void
    {
        if (! isset($this->tokens[$jobId])) {
            return;
        }

        $this->context->leave($this->tokens[$jobId]);
        unset($this->tokens[$jobId]);
    }

    /**
     * The entry's class, taken from the payload's `commandName`.
     *
     * NEVER `resolveName()`: that returns the payload's `displayName`, which
     * `Queue::getDisplayName()` takes from the job's own `displayName()` method, so a
     * job can choose it. `commandName` is written as `get_class($job)` by
     * `Queue::createObjectPayload()` and sits beside it in the same payload. Taking
     * identity from a caller-settable presentation string is the mistake this slice
     * made twice; this is the second place it had to be undone.
     *
     * @return class-string|null
     */
    private function entryClass(Job $job): ?string
    {
        $payload = $job->payload();
        $class = $payload['data']['commandName'] ?? null;

        return is_string($class) && $class !== '' && class_exists($class) ? $class : null;
    }
}
