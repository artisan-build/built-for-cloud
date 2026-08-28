<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Consumes the transactional outbox AFTER commit, idempotently.
 *
 * Delivery of one row is guarded twice:
 *
 * - The CLAIM is a conditional update gated on affected rows: undelivered,
 *   and unclaimed or stale-claimed. Two drains racing over the same row
 *   cannot both win it, and a consumer that dies mid-delivery leaves the
 *   row claimable again once its claim goes stale.
 * - A subscriber that THROWS releases the claim (attempts and last_error
 *   recorded, exception class only), so a later drain retries; the failure
 *   never propagates into whatever ran the drain.
 *
 * The trade, stated: delivery is at-least-once across a process death (a
 * consumer that dies between notifying and marking delivered will cause a
 * re-send after the claim TTL), and exactly-once everywhere short of that.
 * The alternative — mark-then-send — silently LOSES the notification on
 * the same death, which is worse for a security notice.
 */
final class OutboxDrainer
{
    public function __construct(private readonly LifecycleNotifier $notifier) {}

    /**
     * Deliver every claimable row. Returns the number delivered.
     */
    public function drain(): int
    {
        $claimTtl = $this->claimTtlSeconds();

        /** @var list<string> $pending */
        $pending = CredentialOutboxEntry::query()
            ->claimable($claimTtl)
            ->orderBy('created_at')
            ->orderBy('id')
            ->pluck('id')
            ->all();

        $delivered = 0;

        foreach ($pending as $entryId) {
            if ($this->deliver($entryId, $claimTtl)) {
                $delivered++;
            }
        }

        return $delivered;
    }

    private function deliver(string $entryId, int $claimTtl): bool
    {
        $claimed = CredentialOutboxEntry::query()
            ->whereKey($entryId)
            ->claimable($claimTtl)
            ->update([
                'claimed_at' => now(),
                'attempts' => DB::raw('attempts + 1'),
            ]);

        // Zero rows: another consumer claimed or delivered it under us.
        if ($claimed !== 1) {
            return false;
        }

        /** @var CredentialOutboxEntry $entry */
        $entry = CredentialOutboxEntry::query()->findOrFail($entryId);

        /** @var CredentialAuditEvent|null $auditEvent */
        $auditEvent = CredentialAuditEvent::query()->find($entry->audit_event_id);

        try {
            // A missing audit row cannot happen through the recorder (same
            // transaction); tolerate it as already-dealt-with rather than
            // retrying forever.
            if ($auditEvent !== null) {
                $this->notifier->notify($auditEvent);
            }
        } catch (Throwable $exception) {
            // Release the claim: the row stays in the outbox for a later
            // drain. Only the exception CLASS is recorded or logged — a
            // mailer or driver message can echo payload values.
            CredentialOutboxEntry::query()->whereKey($entryId)->update([
                'claimed_at' => null,
                'last_error' => mb_substr($exception::class, 0, 255),
            ]);

            $this->warnAboutFailedDelivery($exception);

            return false;
        }

        CredentialOutboxEntry::query()
            ->whereKey($entryId)
            ->whereNull('delivered_at')
            ->update(['delivered_at' => now()]);

        return true;
    }

    private function claimTtlSeconds(): int
    {
        $configured = config('built-for-cloud.audit.outbox.claim_ttl_seconds', 300);

        return max(1, (int) (is_numeric($configured) ? $configured : 300));
    }

    private function warnAboutFailedDelivery(Throwable $exception): void
    {
        try {
            Log::warning('Built for Cloud could not deliver a lifecycle notification; the outbox row remains claimable.', [
                'exception' => $exception::class,
            ]);
        } catch (Throwable) {
            // Failing to log must not turn a released claim into a crash.
        }
    }
}
