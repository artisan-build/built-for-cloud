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
use Illuminate\Database\QueryException;
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
     * @throws ConsoleKeyRefused when the deployment is unclaimed, the `kid` is taken, or the material is already on file
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
        } catch (InvalidArgumentException|QueryException $refused) {
            // The delivery already validated its `kid` and normalized
            // its material, and both uniqueness checks above passed, so
            // what is left is a concurrent delivery that won one of the
            // two unique indexes between those checks and this line.
            // Re-reading says which, and the answer is a refusal either
            // way — never an integrity violation surfacing as a 500.
            throw ConsoleKeyRefused::because(
                $this->materialIsOnFile($delivery->publicKey)
                    ? ConsoleKeyRefusal::MaterialAlreadyFiled
                    : ConsoleKeyRefusal::KeyIdInUse,
                $refused,
            );
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
     *
     * Marked impure because it genuinely is, and the second call in this
     * class depends on that: it runs AFTER an insert failed, precisely
     * to learn whether a concurrent delivery filed this material in
     * between. A pure reading would let the analyser assume the first
     * call's `false` still holds and collapse that branch.
     *
     * @phpstan-impure
     */
    private function materialIsOnFile(string $publicKey): bool
    {
        return ConsoleKey::query()->where('public_key', $publicKey)->exists();
    }
}
