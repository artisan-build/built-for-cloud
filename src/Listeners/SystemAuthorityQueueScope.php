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
    /**
     * Whether the wrapper's payload POSITIVELY identifies one of our listeners.
     *
     * The frame opens only on positive identification. Any failure to establish
     * identity — ciphertext this listener cannot decrypt, a nested object implementing
     * only the legacy `Serializable` interface, a model deleted since dispatch, a
     * corrupt payload, a class that cannot be loaded — leaves the entry UNFRAMED.
     *
     * That is a ruling, and it was made the hard way. Three separate fail-closed doors
     * each falsely framed HOST work: an encrypted payload, restoration that depends on
     * host `JobProcessing` state, and a legacy-serialisable object in the event. In every
     * case a host listener ran and its own legitimate authentication was silently
     * refused, while the framework — which reads the payload unrestricted, a moment
     * later, after any host listener has configured what it needs — would have run it
     * perfectly well. A false refusal on host code ranks above a package gap, so the
     * residue is disclosed under the class statement and carries a security debt row
     * rather than being guessed at.
     *
     * @param  array<string, mixed>  $payload
     */
    private function wrappedListenerIsOurs(array $payload): bool
    {
        $serialised = $payload['data']['command'] ?? null;

        if (! is_string($serialised)) {
            return false;
        }

        try {
            $plain = str_starts_with($serialised, 'O:')
                ? $serialised
                : $this->encrypter()->decrypt($serialised);
        } catch (Throwable) {
            return false;
        }

        // `allowed_classes` restricted to the wrapper keeps this read inert: the
        // wrapper's `class` is a plain string so it survives, while everything nested
        // becomes __PHP_Incomplete_Class. THE LISTENER IS NEVER CONSTRUCTED AND ITS
        // MODELS ARE NEVER RESTORED — no queries, no __wakeup, no
        // ModelNotFoundException, and no duplicate model loads before
        // `CallQueuedHandler` does its own read.
        //
        // The error handler is scoped and restored in `finally`, never `@`: restricting
        // a legacy-serialisable nested object makes PHP warn that
        // __PHP_Incomplete_Class has no unserialiser, and under the application's
        // handler that warning becomes an exception. `@` happens to work only because
        // Laravel's handler consults error_reporting(), which is an interaction between
        // two behaviours rather than a guarantee.
        set_error_handler(static fn (): bool => true);

        try {
            $command = unserialize($plain, ['allowed_classes' => [CallQueuedListener::class]]);
        } catch (Throwable) {
            return false;
        } finally {
            restore_error_handler();
        }

        return $command instanceof CallQueuedListener
            && is_string($command->class)
            && is_a($command->class, SystemAuthorityQueueEntry::class, true);
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
