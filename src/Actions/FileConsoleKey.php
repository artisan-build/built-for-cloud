<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Throwable;

/**
 * The ONE place a delivered countersigning key becomes a trusted one
 * (Console PRD D12). Three transports reach it — the ownership claim,
 * the onboarding exchange, and the re-key verb over HTTP and CLI — and
 * they reach it with the same arguments, which is what makes the two
 * re-key transports produce identical outcomes rather than merely
 * similar ones.
 *
 * **Make-before-break, and only the first half of it.** A delivery
 * files a NEW key id and activates it. It retires NOTHING — not the key
 * it replaces, not any other row — so from the moment it commits, both
 * the outgoing and incoming keys verify. Retirement is a separate,
 * later {@see ConsoleKeyring::retire()} call whose safe moment is
 * "after every assertion minted under the old key has expired", which
 * D12 bounds at `assertion_max_ttl_seconds`. This class has no code
 * path that retires, which is the property that makes a re-key against
 * a LIVE deployment safe to run at any moment.
 *
 * **Both halves in one transaction.** Filing and activating are two
 * keyring operations on purpose (receiving material is not trusting
 * it), but a DELIVERY through this action is one atomic act: a caller
 * who is handed a `ConsoleKeyFiled` has a key that verifies, and a
 * caller who is handed a refusal has no row at all. A pending row left
 * behind by a half-applied delivery would be invisible custody — key
 * material on file that nobody knows arrived.
 *
 * Every call REQUIRES the caller's open transaction, exactly as
 * {@see LifecycleEventRecorder} does and for the same reason: on the
 * claim surfaces the key filing must live or die with the claim itself,
 * so a refused delivery leaves the claim code unburned and the
 * deployment unclaimed rather than half-converted.
 */
final readonly class FileConsoleKey
{
    public function __construct(
        private ConsoleKeyring $keyring,
        private LifecycleEventRecorder $recorder,
    ) {}

    /**
     * File and activate a delivered key, auditing both steps.
     *
     * MUST be called inside the caller's transaction (the recorder
     * enforces this and throws otherwise).
     *
     * @throws ConsoleKeyRefused when the `kid` is already on file
     */
    public function __invoke(ConsoleKeyDelivery $delivery, ?AuditActor $actor): ConsoleKeyFiled
    {
        if ($this->keyring->find($delivery->keyId) instanceof ConsoleKey) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::KeyIdInUse);
        }

        try {
            $this->keyring->add($delivery->keyId, $delivery->publicKey);
        } catch (InvalidArgumentException|QueryException $refused) {
            // The delivery already validated its `kid` and normalized
            // its material, so the one refusal the ring has left is a
            // `kid` filed between the check above and this line by a
            // concurrent delivery — as the ring's own guard, or as the
            // column's unique index.
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::KeyIdInUse, $refused);
        }

        $key = $this->keyring->activate($delivery->keyId);

        $activeKeyIds = array_map(
            static fn (ConsoleKey $active): string => $active->key_id,
            $this->keyring->active(),
        );

        // Two events for two operations, in the delivery's own
        // transaction. `credential_id` stays NULL: that column names a
        // row in the credential stores, and a console key is neither —
        // the same shape the subject-level `offboarded` event uses,
        // with the identity in the bounded note.
        $this->recorder->record(
            event: LifecycleEventType::Delivered,
            actor: $actor,
            note: 'console countersigning key filed: '.$key->key_id,
        );

        $this->recorder->record(
            event: LifecycleEventType::Activated,
            actor: $actor,
            note: 'console countersigning key activated: '.$key->key_id
                .'; keys now verifying: '.implode(', ', $activeKeyIds),
        );

        return new ConsoleKeyFiled($key, $activeKeyIds);
    }

    /**
     * Audit a REFUSED delivery — the other half of D12's "every
     * verification failure and every successful re-key is audited".
     *
     * It opens its OWN transaction, because the refusal it records is
     * the reason the caller's transaction rolled back (or never opened):
     * an audit row written inside that transaction would roll back with
     * it and the refusal would go unrecorded.
     *
     * Best-effort, matching the operator gate's denial audit
     * ({@see EnsureCredentialAdmin}):
     * a refusal has no state transition to stay transactional with, and
     * an unreachable audit store must not turn a clean 422 into a 500.
     * The honest reading of that trade: this event lands whenever the
     * database is writable, and a deployment whose audit store is down
     * loses refusal records — the refusal itself never depends on it.
     *
     * `$keyId` is written only when it is well-formed. A malformed one
     * is deliberately dropped rather than truncated into the note:
     * unvalidated caller text does not belong in an audit row that
     * renders in an operator's console.
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
                    note: 'console countersigning key delivery refused: '.$refused->reason->value.$named,
                );
            });
        } catch (Throwable) {
            // See the best-effort note above.
        }
    }
}
