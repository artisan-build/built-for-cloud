<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRetired;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use LogicException;
use Throwable;

/**
 * The ONE place a filed countersigning key stops being trusted through
 * an operator surface (Console PRD D12) — the other half of the
 * make-before-break rotation {@see FileConsoleKey} opens, and the caller
 * whose auditing {@see ConsoleKeyring::retire()}'s docblock defers to.
 *
 * It exists because that primitive is reachable only from PHP inside the
 * app. A deployment that has re-keyed could file and activate the
 * incoming key over HTTP or the CLI and then had no operator path to
 * stop trusting the outgoing one, which left every rotation permanently
 * half-finished — two keys verifying, forever, with the older one's
 * private half wherever it had been.
 *
 * Two transports reach this — {@see ManageConsoleKeys::retire} and
 * {@see ConsoleRetireKeyCommand} — with the same arguments, so their
 * EFFECTS are identical. Their AUTHORITY is not, and is not this class's
 * business: each proves its own, above.
 *
 * ## Retiring the LAST ACTIVE key is permitted, and never by accident
 *
 * A deployment with nothing verifying can verify no assertion, so no
 * operator can be handed to it until a fresh key is filed and activated
 * — and the retired key's bytes can never be re-filed, so recovery needs
 * a new keypair from the vendor rather than the one just retired.
 *
 * That is not a reason to refuse it. Ending delegated entry is a thing a
 * deployment is entitled to decide, and a surface that refused outright
 * would leave the only path to it inside a PHP console — which is the
 * gap this class was written to close, reopened one key later. So it is
 * permitted behind an affirmative `$confirmLastActiveKey`, and refused
 * as {@see ConsoleKeyRefusal::LastActiveKey} without one.
 *
 * The check bites ONLY where the retirement would actually end
 * verification: retiring a pending key, or one of two active keys,
 * changes nothing about whether entry is possible and asks for no
 * confirmation.
 *
 * **The decision REQUESTS a row lock on the ring, and a request is all
 * it is.** "Is this the last active key" is read before it is written,
 * so `lockForUpdate()` is asked for over the whole ring — and what that
 * request buys is the DRIVER'S to provide. On one that honours row
 * locks, two concurrent retirements of the last two active keys cannot
 * each read a ring in which the other was still verifying, confirm
 * nothing, and leave the deployment with no key between them. On one
 * that does not — SQLite compiles the clause away and issues no such
 * SQL — the request is a no-op, and nothing here bounds concurrent
 * retirement at all.
 *
 * State it that way rather than "the ring is locked", which is a claim
 * about the call site written as a claim about the query. This
 * package's own suite runs on the driver where it is a no-op, so no
 * green result here is evidence either way; the concurrent case is
 * tracked as debt rather than asserted.
 *
 * ## Retirement is idempotent, and says which call did it
 *
 * Retiring an already-retired key answers `newly_retired: false` and the
 * FIRST call's `retired_at`. That is the same shape the credential
 * revoke verb takes, and it is what a retry after a dropped connection
 * needs: the state the caller asked for holds, and the answer says so
 * without pretending this call is what produced it.
 *
 * The answer is not a frozen copy of the first one — {@see ConsoleKeyRetired}
 * says which parts move and why. `activeKeyIds` is read fresh on every
 * call, so a repeat reports the ring as it stands rather than as it
 * stood.
 *
 * One consequence, stated because it is the honest reading: **a repeat
 * writes no second audit event.** One retirement, one event — an event
 * per CALL would record retirements that never happened.
 *
 * Every call REQUIRES the caller's open transaction, exactly as
 * {@see FileConsoleKey} and {@see LifecycleEventRecorder} do: the audit
 * row is the record of the state change and must live or die with it.
 *
 * **And the check is HERE, not borrowed from the recorder.** The
 * recorder's identical guard runs after this action has already saved
 * `retired_at`, so relying on it produced the one outcome the
 * requirement exists to prevent: a key that had stopped verifying, a
 * caller holding an exception, and no event naming the retirement. The
 * check therefore runs before the lock request and before any read.
 *   Pinned by `tests/ConsoleKeyRetirementTransactionTest.php` — "refuses
 *   to retire outside a database transaction, leaving the key verifying"
 *   and "refuses an already-retired key outside a transaction too, so
 *   the idempotent path cannot slip past the guard".
 *
 * @throws LogicException outside a transaction
 */
final readonly class RetireConsoleKey
{
    public function __construct(
        private ConsoleKeyring $keyring,
        private LifecycleEventRecorder $recorder,
    ) {}

    /**
     * Stop trusting one filed key, auditing the transition.
     *
     * MUST be called inside the caller's transaction (the recorder
     * enforces this and throws otherwise).
     *
     * @throws LogicException outside a transaction, before anything is read or written
     * @throws ConsoleKeyRefused when no key is on file under that id, or when it is the last active key and the caller did not confirm
     */
    public function __invoke(string $keyId, ?AuditActor $actor, bool $confirmLastActiveKey = false): ConsoleKeyRetired
    {
        // FIRST, before the lock request, before any read, and before anything
        // can be written. Leaning on the recorder's identical check was
        // not the same thing and the difference was the whole defect:
        // the recorder is reached only AFTER `retired_at` has been
        // saved, so a caller with no transaction open got a key that had
        // stopped verifying, an exception, and no event anywhere naming
        // the retirement. That is the property AC4 asks for, inverted.
        //
        // It applies to the already-retired path too, which writes
        // nothing and could be argued out of it. Exempting that path
        // would make "does this call need a transaction" depend on ring
        // state the caller cannot see before calling.
        if (DB::transactionLevel() === 0) {
            throw new LogicException(
                'A console key retirement records inside the transaction that performs it, never outside one.',
            );
        }

        // A malformed id cannot name a row, so it takes the same answer
        // rather than a second refusal path that would have to describe
        // unvalidated caller text.
        if (! ConsoleKeyring::isValidKeyId($keyId)) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::UnknownKeyId);
        }

        // The whole ring, with a row lock REQUESTED: the
        // last-active-key decision below is a read that a write depends
        // on. Whether a concurrent retirement can change the answer in
        // between is the driver's answer, not this line's — see the
        // class docblock.
        $ring = ConsoleKey::query()->lockForUpdate()->orderBy('key_id')->get();

        $key = $ring->firstWhere('key_id', $keyId);

        if (! $key instanceof ConsoleKey) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::UnknownKeyId);
        }

        // ONE reading of the clock decides both halves, so a key cannot
        // be active for the count and retired for the check.
        $at = CarbonImmutable::now();

        if ($key->isRetiredAt($at)) {
            return $this->retired($key, newlyRetired: false);
        }

        $activeIds = $this->activeIdsIn($ring, $at);

        if (! $confirmLastActiveKey && $activeIds === [$keyId]) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::LastActiveKey);
        }

        $retired = $this->keyring->retire($keyId);

        $remaining = array_values(array_filter($activeIds, static fn (string $id): bool => $id !== $keyId));

        // ONE event, in the caller's own transaction, with the actor
        // typed. `credential_id` stays NULL: that column names a row in
        // the credential stores and a console key is neither — the same
        // shape the filing events use, with the identity in the bounded
        // note.
        //
        // `revoked` rather than an event of its own: retirement is the
        // only revocation a console key has, and the filing half of this
        // rotation already rides this stream, so an operator reading one
        // rotation reads it as one contiguous story.
        $this->recorder->record(
            event: LifecycleEventType::Revoked,
            actor: $actor,
            note: 'console countersigning key retired: '.$retired->key_id
                .'; keys still verifying: '.($remaining === [] ? 'none' : implode(', ', $remaining)),
        );

        return $this->retired($retired, newlyRetired: true);
    }

    /**
     * Audit a REFUSED retirement, on its own transaction and
     * best-effort, for the reasons {@see FileConsoleKey::recordRefusal}
     * states: the refusal is why the caller's transaction rolled back,
     * and an unreachable audit store must not turn a clean refusal into
     * a 500.
     *
     * `$keyId` is written only when it is well-formed, so unvalidated
     * caller text never reaches a row that renders in an operator's
     * console.
     */
    public function recordRefusal(ConsoleKeyRefused $refused, ?AuditActor $actor, ?string $keyId = null): void
    {
        $named = $keyId !== null && ConsoleKeyring::isValidKeyId($keyId)
            ? ' (key id '.$keyId.')'
            : '';

        try {
            DB::transaction(function () use ($refused, $actor, $named): void {
                $this->recorder->record(
                    event: LifecycleEventType::DeniedAction,
                    actor: $actor,
                    note: 'console countersigning key retirement refused: '.$refused->reason->value.$named,
                );
            });
        } catch (Throwable) {
            // Best effort, exactly as the operator gate's own denial
            // audit is ({@see EnsureCredentialAdmin}).
        }
    }

    /**
     * The result shape, reading what still verifies from the ring rather
     * than from the pre-retirement snapshot.
     */
    private function retired(ConsoleKey $key, bool $newlyRetired): ConsoleKeyRetired
    {
        $active = array_map(
            static fn (ConsoleKey $key): string => $key->key_id,
            $this->keyring->active(),
        );

        return new ConsoleKeyRetired($key->key_id, $key->retired_at, $newlyRetired, array_values($active));
    }

    /**
     * Every key id verifying at one instant, read from the rows already
     * fetched rather than by a second query — a re-read would be a
     * second reading of the ring, which is the thing the lock request
     * above is there to make unnecessary on a driver that honours it.
     *
     * @param  Collection<int, ConsoleKey>  $ring
     * @return list<string>
     */
    private function activeIdsIn(Collection $ring, CarbonImmutable $at): array
    {
        return array_values(array_map(
            static fn (ConsoleKey $key): string => $key->key_id,
            array_filter(
                $ring->all(),
                static fn (ConsoleKey $key): bool => $key->isActiveAt($at),
            ),
        ));
    }
}
