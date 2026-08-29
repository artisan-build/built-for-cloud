<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * The ONE way a verified assertion becomes a delegated session — the API
 * PR4's `/bfc/console/enter` endpoint calls, and the reason PR4 cannot
 * get the ordering wrong.
 *
 * Four things have to happen together at redemption, and each of them
 * is a security property that fails quietly if it is skipped:
 *
 *  1. **The handoff is recorded** on the shadow actor row, refreshing its
 *     `last_handoff_*` copy — including for an actor that is about to be
 *     refused, so an operator can see that a contained human attempted
 *     entry and with what claims. It is committed on its own, BEFORE the
 *     decision, precisely so a refusal cannot roll the record back.
 *  2. **The actor is re-read UNDER A ROW LOCK, and a deactivated one is
 *     refused BEFORE anything is logged in.** Two separate races close
 *     here. The provider only refuses on the NEXT rehydration, so an
 *     endpoint that logged in first would give a contained principal the
 *     whole redemption request — long enough to act. And checking
 *     `deactivated_at` on the model written a moment earlier is a read
 *     that has already gone stale: a concurrent offboard committing
 *     between that write and the login would be missed entirely.
 *     {@see DelegatedActor::deactivate()} takes the same lock, so the
 *     two strictly order.
 *  3. **The claims are bound to the SESSION**, not read later off the
 *     shared row. PRD D8 makes them per-mint; {@see DelegatedClaims}
 *     carries the escalation this prevents.
 *  4. **The login happens only after all of the above, and INSIDE the
 *     transaction that still holds the lock.** An earlier revision
 *     closed the transaction on the locked read and then began the
 *     session outside it — which reopens the whole race it had just
 *     closed: a deactivation committing in that window leaves a live
 *     delegated session behind a row that says contained. The lock is
 *     held from the re-read until the session exists.
 *
 * Exposing these as separate calls would make step 2 optional and step 3
 * forgettable, so they are one method. Verification is NOT part of it:
 * {@see AssertionVerifier} is the crypto choke point and the `jti` burn
 * is a storage decision that belongs to the endpoint owning the
 * transaction — this class takes an assertion that has ALREADY been
 * verified, exactly as {@see Assertion} demands.
 *
 * The session write and the login are not themselves transactional and
 * cannot be rolled back, which is safe in this order: they are the LAST
 * things to happen, nothing after them can fail, and the surrounding
 * transaction performs no write of its own that a rollback would need to
 * undo — it exists to hold the lock.
 *
 * KNOWN LIMIT, stated: `lockForUpdate()` compiles to nothing on SQLite,
 * so this package's own suite cannot prove the ORDERING — only that the
 * re-read happens inside the transaction and that a row deactivated
 * before the re-read is refused. A mutation-debt row records it.
 */
final readonly class ConsoleHandoff
{
    public function __construct(private AuthManager $auth) {}

    /**
     * Redeem a VERIFIED assertion into a live delegated session.
     *
     * @throws DelegatedActorDeactivated when this deployment has contained the actor
     */
    public function redeem(Assertion $assertion, Session $session): DelegatedActor
    {
        $guard = $this->guard();

        // Step 1, committed on its own: the attempt is on file whatever
        // the decision below turns out to be.
        $recorded = DelegatedActor::recordHandoff($assertion);

        /** @var DelegatedActor */
        return DB::transaction(function () use ($assertion, $guard, $recorded, $session): DelegatedActor {
            // Re-read under the lock rather than trusting the model just
            // written: a concurrent deactivation may have committed in
            // between, and this is the read the login has to be based on.
            $locked = DelegatedActor::lockedById($recorded->getKey());

            if ($locked === null || ! $locked->isActive()) {
                throw DelegatedActorDeactivated::cannotEnter();
            }

            // Still inside the transaction, still holding the lock.
            ConsoleSession::begin($session, $assertion);

            $guard->login($locked);

            return $locked;
        });
    }

    private function guard(): ConsoleGuard
    {
        if (! ConsoleGuardConfiguration::enabled()) {
            throw new RuntimeException('The Console is not enabled on this deployment; set built-for-cloud.console.enabled to redeem a console handoff.');
        }

        $guard = $this->auth->guard(ConsoleGuardConfiguration::GUARD);

        if (! $guard instanceof ConsoleGuard) {
            // The app replaced the reserved guard with one of its own.
            // Redeeming into it would mean logging a delegated actor into
            // a guard whose clocks, claims and refusals this package knows
            // nothing about, so this fails loudly instead.
            throw new RuntimeException('The bfc-console guard has been replaced by this application, so the package cannot redeem a console handoff into it.');
        }

        return $guard;
    }
}
