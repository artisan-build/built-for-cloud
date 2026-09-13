<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
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

    public function finished(JobProcessed|JobExceptionOccurred|JobFailed $event): void
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

    /** @return class-string|null */
    private function entryClass(Job $job): ?string
    {
        $name = $job->resolveName();

        if (! is_string($name) || $name === '') {
            return null;
        }

        $class = strstr($name, '@', true) ?: $name;

        return class_exists($class) ? $class : null;
    }
}
