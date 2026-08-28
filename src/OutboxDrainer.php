<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Consumes the transactional outbox AFTER commit, idempotently.
 *
 * Delivery of one row is guarded three ways:
 *
 * - The CLAIM is a conditional update gated on affected rows: undelivered,
 *   and unclaimed or stale-claimed. Two drains racing over the same row
 *   cannot both win it, and a consumer that dies mid-delivery leaves the
 *   row claimable again once its claim goes stale (the TTL sits well above
 *   a slow mail send; `built-for-cloud.audit.outbox.claim_ttl_seconds`).
 * - Each RECIPIENT is marked on the row immediately after its send
 *   succeeds, so a partial failure (the issuer's send landed, the holder's
 *   threw) retries only the recipients not yet marked — never a resend to
 *   everyone.
 * - A subscriber that THROWS releases the claim (attempts and last_error
 *   recorded, exception class only), keeping the per-recipient markers
 *   already written, so a later drain finishes the remainder; the failure
 *   never propagates into whatever ran the drain.
 *
 * The honest delivery contract: deduplication happens at ENQUEUE (the
 * outbox dedup key), sends are tracked per recipient, and a crash in the
 * window between a send and its marker re-sends to that one recipient —
 * at-least-once on crash windows, exactly-once everywhere short of that.
 * The alternative — mark-then-send — silently LOSES the notification on
 * the same crash, which is worse for a security notice.
 */
final class OutboxDrainer
{
    public function __construct(private readonly LifecycleNotifier $notifier) {}

    /**
     * Deliver every claimable row. Returns the number of rows fully
     * delivered (every resolved recipient marked).
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
                $this->deliverToUnmarkedRecipients($entry, $auditEvent);
            }
        } catch (Throwable $exception) {
            // Release the claim: the row stays in the outbox for a later
            // drain, which skips the recipients already marked. Only the
            // exception CLASS is recorded or logged — a mailer or driver
            // message can echo payload values.
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

    /**
     * Send to each resolved recipient not yet marked on the row, marking
     * each one the moment its send returns. The claim gate above means no
     * other consumer is reading or writing this row's markers concurrently.
     */
    private function deliverToUnmarkedRecipients(CredentialOutboxEntry $entry, CredentialAuditEvent $auditEvent): void
    {
        $deliveredRecipients = $entry->delivered_recipients ?? [];

        foreach ($this->notifier->recipientEmails($auditEvent) as $email) {
            if (array_key_exists($email, $deliveredRecipients)) {
                continue;
            }

            $this->notifier->deliverTo($email, $auditEvent);

            $deliveredRecipients[$email] = now()->toIso8601String();

            CredentialOutboxEntry::query()
                ->whereKey($entry->id)
                ->update(['delivered_recipients' => json_encode($deliveredRecipients)]);
        }
    }

    private function claimTtlSeconds(): int
    {
        $configured = config('built-for-cloud.audit.outbox.claim_ttl_seconds', 600);

        return max(1, (int) (is_numeric($configured) ? $configured : 600));
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
