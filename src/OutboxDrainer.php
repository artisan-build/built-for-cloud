<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

/**
 * Consumes the transactional outbox AFTER commit, idempotently.
 *
 * Delivery of one row is guarded four ways:
 *
 * - The CLAIM is a conditional update gated on affected rows: undelivered,
 *   and unclaimed or stale-claimed. Two drains racing over the same row
 *   cannot both win it, and a consumer that dies mid-delivery leaves the
 *   row claimable again once its claim goes stale (the TTL sits well above
 *   a slow mail send; `built-for-cloud.audit.outbox.claim_ttl_seconds`).
 * - Every claim writes a unique CLAIM TOKEN, and EVERY later write for the
 *   row — marker updates, release, completion — is fenced on
 *   `claim_token = mine`. Claim expiry permits a new owner to take over a
 *   stalled drain's row; the fence is what stops the stale owner from then
 *   clobbering the new owner's work: its next fenced write hits zero rows
 *   and it halts that row immediately, sending nothing further. The
 *   per-recipient loop also RE-READS the row under the fence before each
 *   send, so a stale owner cannot re-send to a recipient the new owner
 *   already delivered and marked.
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
 * the same crash, which is worse for a security notice. What the fence
 * removes is the cross-owner class: marker erasure and a stale owner
 * clearing or completing a claim it no longer holds.
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
        $claimToken = (string) Str::uuid();

        $claimed = CredentialOutboxEntry::query()
            ->whereKey($entryId)
            ->claimable($claimTtl)
            ->update([
                'claimed_at' => now(),
                'claim_token' => $claimToken,
                'attempts' => DB::raw('attempts + 1'),
            ]);

        // Zero rows: another consumer claimed or delivered it under us.
        if ($claimed !== 1) {
            return false;
        }

        $entry = $this->fencedRead($entryId, $claimToken);

        if ($entry === null) {
            // Taken over between our claim and this read; the new owner
            // owns all further bookkeeping for the row.
            $this->warnAboutLostOwnership();

            return false;
        }

        /** @var CredentialAuditEvent|null $auditEvent */
        $auditEvent = CredentialAuditEvent::query()->find($entry->audit_event_id);

        try {
            // A missing audit row cannot happen through the recorder (same
            // transaction); tolerate it as already-dealt-with rather than
            // retrying forever.
            if ($auditEvent !== null && ! $this->deliverToUnmarkedRecipients($entryId, $claimToken, $auditEvent)) {
                return false;
            }
        } catch (Throwable $exception) {
            // Release the claim — FENCED: if a new owner already took the
            // row, this write is a no-op and their claim stands untouched.
            // The row stays in the outbox for a later drain, which skips
            // the recipients already marked. Only the exception CLASS is
            // recorded or logged — a mailer or driver message can echo
            // payload values.
            CredentialOutboxEntry::query()
                ->whereKey($entryId)
                ->where('claim_token', $claimToken)
                ->update([
                    'claimed_at' => null,
                    'claim_token' => null,
                    'last_error' => mb_substr($exception::class, 0, 255),
                ]);

            $this->warnAboutFailedDelivery($exception);

            return false;
        }

        // Completion, fenced the same way: zero rows means ownership moved
        // and the new owner decides when the row is delivered.
        return CredentialOutboxEntry::query()
            ->whereKey($entryId)
            ->where('claim_token', $claimToken)
            ->whereNull('delivered_at')
            ->update(['delivered_at' => now()]) === 1;
    }

    /**
     * Send to each resolved recipient not yet marked on the row, marking
     * each one the moment its send returns. Before EVERY send the row is
     * re-read under the ownership fence — fresh markers, current owner —
     * and every marker write carries the fence too. Returns false the
     * moment ownership is lost; the caller stops the row there.
     */
    private function deliverToUnmarkedRecipients(string $entryId, string $claimToken, CredentialAuditEvent $auditEvent): bool
    {
        foreach ($this->notifier->recipientEmails($auditEvent) as $email) {
            $entry = $this->fencedRead($entryId, $claimToken);

            if ($entry === null) {
                $this->warnAboutLostOwnership();

                return false;
            }

            $deliveredRecipients = $entry->delivered_recipients ?? [];

            if (array_key_exists($email, $deliveredRecipients)) {
                continue;
            }

            $this->notifier->deliverTo($email, $auditEvent);

            $deliveredRecipients[$email] = now()->toIso8601String();

            $marked = CredentialOutboxEntry::query()
                ->whereKey($entryId)
                ->where('claim_token', $claimToken)
                ->update(['delivered_recipients' => json_encode($deliveredRecipients)]);

            if ($marked !== 1) {
                // Ownership moved between the send and its marker: the one
                // unavoidable at-least-once window. Stop immediately — the
                // new owner's markers are the truth now.
                $this->warnAboutLostOwnership();

                return false;
            }
        }

        return true;
    }

    private function fencedRead(string $entryId, string $claimToken): ?CredentialOutboxEntry
    {
        /** @var CredentialOutboxEntry|null */
        return CredentialOutboxEntry::query()
            ->whereKey($entryId)
            ->where('claim_token', $claimToken)
            ->first();
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

    private function warnAboutLostOwnership(): void
    {
        try {
            Log::warning('Built for Cloud stopped a stale outbox consumer: the row was claimed by a newer owner.');
        } catch (Throwable) {
            // Failing to log must not turn a clean halt into a crash.
        }
    }
}
