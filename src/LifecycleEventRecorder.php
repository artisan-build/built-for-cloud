<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use LogicException;
use Throwable;

/**
 * The single emission point of the lifecycle event stream (D8 adjustments
 * 2 & 3, SEC-V3-09): one call appends the audit row AND the outbox row, and
 * REQUIRES the caller's open database transaction — the stream is
 * transactional, or it is fiction. A state transition that rolls back takes
 * its audit row and its outbox row with it, so nothing is ever delivered
 * about a mutation that did not happen.
 *
 * Consumption is decoupled: an after-commit hook drains the outbox
 * synchronously (the simplest honest shape for this PR — no queue
 * dependency, and `bfc:outbox:drain` re-drains anything a dead process
 * left behind). afterCommit callbacks are discarded on rollback, so a
 * failed transaction triggers no drain.
 *
 * `$drainAfterCommit` turns that hook off for one call. It exists for
 * events emitted from POLLED routes: a drain is O(claimable rows) and
 * may send mail, so hanging it off a request the vendor makes sixty
 * times a minute is an amplification lever regardless of how cheap the
 * event itself is. The audit row and the outbox row are still written
 * transactionally; only the delivery attempt moves to the next drain.
 */
final class LifecycleEventRecorder
{
    public function record(
        LifecycleEventType $event,
        ?string $credentialId = null,
        ?string $codeId = null,
        ?AuditActor $actor = null,
        ?string $recipient = null,
        ?int $codeTtlSeconds = null,
        ?CarbonInterface $credentialExpiresAt = null,
        ?AuditReason $reason = null,
        ?string $note = null,
        ?string $supersededByCredentialId = null,
        ?string $dedupKey = null,
        bool $drainAfterCommit = true,
    ): CredentialAuditEvent {
        if (DB::transactionLevel() === 0) {
            throw new LogicException(
                'Lifecycle events record inside the state transition\'s own transaction, never outside one.',
            );
        }

        $auditEvent = CredentialAuditEvent::query()->create([
            'id' => (string) Str::uuid(),
            'event' => $event,
            'code_id' => $codeId,
            'credential_id' => $credentialId,
            'superseded_by_credential_id' => $supersededByCredentialId,
            'provider' => $this->contextValue('built-for-cloud.product'),
            'deployment' => $this->contextValue('built-for-cloud.cloud.application'),
            'environment' => app()->environment(),
            'actor_type' => $actor?->type,
            'actor_ref' => $actor?->ref,
            'recipient' => $recipient,
            'code_ttl_seconds' => $codeTtlSeconds,
            'credential_expires_at' => $credentialExpiresAt,
            'reason_code' => $reason,
            'note' => $note === null ? null : mb_substr($note, 0, 500),
            'occurred_at' => now(),
        ]);

        // A duplicate dedup key fails this insert — and with it the whole
        // transaction. That is the intended shape: the same logical event
        // is never enqueued (and so never delivered) twice.
        CredentialOutboxEntry::query()->create([
            'id' => (string) Str::uuid(),
            'audit_event_id' => $auditEvent->id,
            'dedup_key' => $dedupKey ?? $auditEvent->id,
        ]);

        // The outbox row is written either way; only the SYNCHRONOUS
        // drain is optional. A caller passes false when its event rides
        // a high-frequency request — the Console vitals read is polled up
        // to sixty times a minute per credential, and draining every
        // claimable row (and sending its notifications) on each poll
        // turns a dashboard into a database and mail amplifier. Those
        // rows stay claimable and are delivered by `bfc:outbox:drain` or
        // by the next mutating request's drain, so nothing is lost;
        // what changes is that a READ no longer does other events'
        // delivery work.
        if (! $drainAfterCommit) {
            return $auditEvent;
        }

        // Post-commit bookkeeping must NEVER fail the request the mutation
        // already earned: by the time this runs the transition is committed,
        // and an exception here (a dropped connection, a broken mailer)
        // would surface as a 500 that invites the client to retry a
        // remint/revoke that already happened. Swallow, log the class only;
        // the outbox row stays claimable for `bfc:outbox:drain`.
        DB::afterCommit(static function (): void {
            try {
                app(OutboxDrainer::class)->drain();
            } catch (Throwable $exception) {
                try {
                    Log::warning('Built for Cloud deferred outbox delivery to a later drain.', [
                        'exception' => $exception::class,
                    ]);
                } catch (Throwable) {
                    // Failing to log must not resurrect the failure.
                }
            }
        });

        return $auditEvent;
    }

    private function contextValue(string $key): ?string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
