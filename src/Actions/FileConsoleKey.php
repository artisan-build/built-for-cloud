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
use ArtisanBuild\BuiltForCloud\Ownership;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Throwable;

/**
 * The ONE place a delivered countersigning key becomes a trusted one
 * (Console PRD D12). Four transports reach it — the ownership claim, the
 * onboarding exchange, the re-key route and the CLI verb — and they
 * reach it with the same arguments, which is what makes their EFFECTS
 * identical rather than merely similar. Their AUTHORITY is not identical
 * and is not this class's business: each caller proves its own, above.
 *
 * What is at stake, because it governs every rule below: a filed key is
 * a standing authority to mint delegated-ADMIN entry into this
 * deployment. Whoever holds the matching private half can enter as an
 * admin, repeatedly, from anywhere, until the key is retired. Every
 * write here is therefore a takeover path, and the refusals are gates
 * rather than input validation.
 *
 * The rules, in the order they are checked:
 *
 * 1. **The deployment must be claimed.** A key names who may enter as
 *    admin; a deployment with no owner has not decided who that is. The
 *    ownership row is LOCKED for the check, and the ownership claim
 *    satisfies it by establishing the owner earlier in the very same
 *    transaction.
 * 2. **The key id must be free.** Rebinding a live `kid` to different
 *    bytes is key substitution — the one write that would let a
 *    mis-delivered key inherit an already-trusted name.
 * 3. **The material must not already be on file**, in ANY lifecycle
 *    state including retired. Retirement is the only revocation this
 *    design has, and a retired key whose bytes can be re-filed under a
 *    fresh `kid` was never really retired.
 *
 * Rules 2 and 3 are read checks backed by unique indexes. The reads
 * answer every delivery an operator actually makes; the indexes are what
 * hold when two deliveries race, and a delivery that loses that race is
 * refused as {@see ConsoleKeyRefusal::ConcurrentDelivery} without any
 * attempt to say which index it lost to.
 *
 * **Make-before-break, and only the first half of it.** A delivery files
 * a NEW key id and activates it. It retires NOTHING — not the key it
 * replaces, not any other row — so from the moment it commits, both the
 * outgoing and incoming keys verify. Retirement is a separate, later
 * {@see ConsoleKeyring::retire()} call whose safe moment is "after every
 * assertion minted under the old key has expired", which D12 bounds at
 * `assertion_max_ttl_seconds`. This class has no code path that retires,
 * which is the property that makes a re-key against a LIVE deployment
 * safe to run at any moment.
 *
 * **Both halves in one transaction.** Filing and activating are two
 * keyring operations on purpose (receiving material is not trusting it),
 * but a DELIVERY through this action is one atomic act: a caller who is
 * handed a `ConsoleKeyFiled` has a key that verifies, and a caller who
 * is handed a refusal has no row at all. A pending row left behind by a
 * half-applied delivery would be invisible custody — key material on
 * file that nobody knows arrived.
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
     * @throws ConsoleKeyRefused when the deployment is unclaimed, the `kid` is taken, the material is already on file, or a concurrent delivery won the race
     */
    public function __invoke(ConsoleKeyDelivery $delivery, ?AuditActor $actor): ConsoleKeyFiled
    {
        $this->requireClaimedDeployment();

        if ($this->keyring->find($delivery->keyId) instanceof ConsoleKey) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::KeyIdInUse);
        }

        if ($this->materialIsOnFile($delivery->publicKey)) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::MaterialAlreadyFiled);
        }

        try {
            $this->keyring->add($delivery->keyId, $delivery->publicKey);
        } catch (InvalidArgumentException|UniqueConstraintViolationException $lost) {
            // A LOST RACE, and nothing else. The delivery validated its
            // `kid` and normalized its material before it got here, and
            // both uniqueness checks above just passed, so the only way
            // the ring can still refuse is that a concurrent delivery
            // filed a conflicting row in between — as the ring's own
            // re-check ({@see InvalidArgumentException}) or as one of
            // the two unique indexes.
            //
            // The reason is deliberately the single
            // {@see ConsoleKeyRefusal::ConcurrentDelivery} rather than a
            // guess at WHICH constraint lost. Working that out would
            // mean re-reading the table, and PostgreSQL fails every
            // statement in a transaction a unique violation has aborted
            // (SQLSTATE 25P02) — so the re-read would itself throw and
            // the caller would get a 500 where a 409 was promised. The
            // alternative, matching driver-specific error text, is the
            // kind of thing that works until someone changes database.
            //
            // The catch is narrow on purpose too: a connection drop, a
            // permission failure or a full disk is NOT a refusal, and
            // reporting one as "that key id is taken" would send an
            // operator hunting a key that is not there. Those keep
            // travelling as the server errors they are.
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::ConcurrentDelivery, $lost);
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

        return new ConsoleKeyFiled($key->key_id, $key->activated_at, $activeKeyIds);
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
     * ({@see EnsureCredentialAdmin}): a refusal has no state transition
     * to stay transactional with, and an unreachable audit store must
     * not turn a clean 422 into a 500. The honest reading of that trade:
     * this event lands whenever the database is writable, and a
     * deployment whose audit store is down loses refusal records — the
     * refusal itself never depends on it.
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

    /**
     * Refuse to key a deployment nobody owns (rework A6).
     *
     * This was previously asserted in a docblock and enforced by nothing
     * — the reasoning being that an unclaimed deployment has issued no
     * operator credential. That reasoning was wrong:
     * `bfc:install:operator-credential` mints one from the host, before
     * and independently of any ownership claim, so the retrofit path
     * could key a deployment with no owner at all.
     *
     * The row is LOCKED rather than merely read, so a claim committing
     * concurrently cannot let this check pass against state the filing
     * then contradicts.
     *
     * @throws ConsoleKeyRefused
     */
    private function requireClaimedDeployment(): void
    {
        $ownership = Ownership::query()->lockForUpdate()->first();

        if ($ownership === null || $ownership->owner_token_id === null) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::Unclaimed);
        }
    }

    /**
     * Whether these exact bytes are already filed, in ANY lifecycle
     * state — retired included, which is the state that matters
     * (rework B4).
     *
     * `$publicKey` is the delivery's normalized storage form, so this
     * compares like for like: the same key delivered as hex and as
     * base64url is the same row, not two.
     */
    private function materialIsOnFile(string $publicKey): bool
    {
        return ConsoleKey::query()->where('public_key', $publicKey)->exists();
    }
}
