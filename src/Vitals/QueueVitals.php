<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Vitals;

/**
 * The queue/job backlog block of the vitals payload (Console PRD D9).
 * Four integers, every one of them nullable, and null carries exactly one
 * meaning: **this endpoint did not obtain the number.** It never means
 * zero.
 *
 * There are two ways a member lands null, and the payload does not
 * distinguish them — {@see VitalsPayload::$health} does:
 *
 * 1. The driver does not report it. Only the `database` queue driver
 *    exposes the pending/reserved split and an enqueue time to the
 *    package; every other driver reports `pending` from the connection's
 *    own `size()` and nulls the rest. Health stays `ok`: nothing failed.
 * 2. The read FAILED (the queue store is unreachable, its table is
 *    missing). Health degrades — {@see CollectVitals} accumulates that
 *    per read — and the payload still serves (D9).
 */
final readonly class QueueVitals
{
    public function __construct(
        public ?int $pending = null,
        public ?int $reserved = null,
        public ?int $failed = null,
        public ?int $oldestPendingAgeSeconds = null,
    ) {}

    /**
     * @return array{pending: int|null, reserved: int|null, failed: int|null, oldest_pending_age_seconds: int|null}
     */
    public function toArray(): array
    {
        return [
            'pending' => $this->pending,
            'reserved' => $this->reserved,
            'failed' => $this->failed,
            'oldest_pending_age_seconds' => $this->oldestPendingAgeSeconds,
        ];
    }
}
