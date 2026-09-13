<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Queue\Job;
use Illuminate\Events\CallQueuedListener;
use Illuminate\Queue\Events\JobAttempted;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Queue\Events\JobProcessing;
use Throwable;

final class SystemAuthorityQueueScope
{
    /** @var array<int, int> */
    private array $tokens = [];

    public function __construct(private readonly SystemAuthorityContext $context) {}

    public function processing(JobProcessing $event): void
    {
        if (! $this->shouldFrame($event->job)) {
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

    /**
     * Whether this job is one of the package's own queue entries.
     *
     * Identity comes from the payload's `commandName`, which `Queue::createObjectPayload()`
     * writes as `get_class($job)` — never `resolveName()`, which returns the
     * caller-settable `displayName`.
     *
     * A queued LISTENER is executed inside `CallQueuedListener`, so for those
     * `commandName` names the wrapper and the marked class sits on the wrapper's own
     * `class` property. Reading it means unserialising the command, which is what
     * `CallQueuedHandler` does moments later anyway — but doing it here is not free:
     * `SerializesModels` restores models during unserialisation, so a job whose model
     * has since been deleted throws. If that escaped this listener it would turn a job
     * the framework would quietly delete under `deleteWhenMissingModels` into a
     * failure. So: unserialise ONLY for the wrapper, never let anything out, and frame
     * the entry when its class cannot be read.
     */
    private function shouldFrame(Job $job): bool
    {
        $payload = $job->payload();
        $class = $payload['data']['commandName'] ?? null;

        if (! is_string($class) || $class === '' || ! class_exists($class)) {
            return false;
        }

        if ($class !== CallQueuedListener::class) {
            return is_a($class, SystemAuthorityQueueEntry::class, true);
        }

        return $this->wrappedListenerIsOurs($payload);
    }

    /** @param array<string, mixed> $payload */
    private function wrappedListenerIsOurs(array $payload): bool
    {
        $serialised = $payload['data']['command'] ?? null;

        if (! is_string($serialised)) {
            return true;
        }

        try {
            // Read it the way the framework reads it. `CallQueuedHandler::getCommand()`
            // treats a payload starting `O:` as plain serialised and DECRYPTS anything
            // else, because a `ShouldBeEncrypted` entry's command is ciphertext. Without
            // that branch every encrypted entry failed to unserialise and fell to the
            // fail-closed path, which framed HOST work and silently refused a host
            // listener's own legitimate authentication.
            $plain = str_starts_with($serialised, 'O:')
                ? $serialised
                : $this->encrypter()->decrypt($serialised);

            // `allowed_classes` restricted to the wrapper is what makes reading this
            // safe. The wrapper's `class` is a plain string, so it survives, while
            // everything nested becomes __PHP_Incomplete_Class — so the LISTENER IS
            // NEVER CONSTRUCTED AND ITS MODELS ARE NEVER RESTORED. That removes the
            // whole hazard of reading a payload here: no database queries, no __wakeup,
            // no ModelNotFoundException for a row deleted since dispatch, and no
            // duplicate model loads before CallQueuedHandler does its own read.
            $command = unserialize($plain, ['allowed_classes' => [CallQueuedListener::class]]);
        } catch (Throwable) {
            // Fail CLOSED, and silently: the entry is framed, and a restoration failure
            // stays the framework's to handle.
            return true;
        }

        if (! $command instanceof CallQueuedListener || ! is_string($command->class)) {
            return true;
        }

        return is_a($command->class, SystemAuthorityQueueEntry::class, true);
    }

    private function encrypter(): Encrypter
    {
        return app(Encrypter::class);
    }

    private function leave(int $jobId): void
    {
        if (! isset($this->tokens[$jobId])) {
            return;
        }

        $this->context->leave($this->tokens[$jobId]);
        unset($this->tokens[$jobId]);
    }
}
