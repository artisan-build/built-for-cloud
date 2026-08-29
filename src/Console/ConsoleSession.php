<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use Illuminate\Contracts\Session\Session;

/**
 * The SESSION CONTRACT of a delegated console session: everything the
 * enter endpoint (PR4) writes at redemption, and the only place a live
 * request reads a delegated claim from.
 *
 * TWO things live here, for two different reasons.
 *
 * **The assertion's issued-at**, which is what makes D7's cap an
 * ASSERTION-age cap: the clock the vendor started when it minted is the
 * clock that runs out, so an operator cannot extend a delegated session
 * by holding a mint before redeeming it. It is written once and never
 * refreshed — refreshing it is exactly the sliding behaviour the absolute
 * cap exists to forbid.
 *
 * **The handoff's claims** (display name, role, agency), because PRD D8
 * makes them per-mint and never cached beyond the session. The shadow
 * actor row cannot hold them: it is shared by every live session for the
 * same subject, so writing a later handoff's `admin` onto it would
 * promote an already-live `member` session on its next request. Binding
 * them here means one session's authority is fixed at the moment its own
 * assertion was redeemed and can only change by redeeming another one.
 *
 * Both live in the session and nowhere the browser can reach: it carries
 * an opaque session cookie and never sees, sends, or can edit any of
 * this. A client-supplied age would be a client-controlled revocation,
 * and a client-supplied role would be a client-controlled promotion.
 *
 * Reads are ATOMIC and FAIL CLOSED: {@see claims()} returns a complete
 * {@see DelegatedClaims} or null, never a half-populated one.
 *
 * THIS CLASS ONLY READS. It used to carry a public static `begin()` that
 * wrote all four keys from an {@see Assertion} — which meant the package
 * handed out a public way to assemble a delegated session's claims from
 * an assertion nothing had verified, next door to a `redeem()` built
 * precisely so that could not happen. The write now lives inside
 * {@see ConsoleGuard::redeem()}, private, after verification and inside
 * the transaction holding the actor's row lock. The keys stay here
 * because the CONTRACT is one thing, and PR4/PR5/PR7 read it.
 *
 * THE BOUNDARY, stated so the guarantee is not read as more than it is:
 * anything that can write the session store can write these four keys
 * and the guard's own login key, and a session assembled that way is
 * indistinguishable from a redeemed one. That is irreducible — it is
 * what this package's own tests do to reach states a real redemption
 * cannot produce (a capped clock, a broken marker) — and it is not a
 * hole in §4.3, which is about credentials and login paths. The claim
 * that IS made and held: no package API assembles a delegated session
 * without verified assertion bytes.
 */
final class ConsoleSession
{
    /**
     * The assertion's `iat` as a Unix timestamp (seconds).
     */
    public const string ASSERTION_ISSUED_AT = 'bfc_console.assertion_issued_at';

    /** This session's display name — the handoff's, not the row's. */
    public const string DISPLAY_NAME = 'bfc_console.display_name';

    /** This session's role (D8) — the handoff's, not the row's. */
    public const string ROLE = 'bfc_console.role';

    /** This session's agency (D4), or absent for a direct operator. */
    public const string ON_BEHALF_OF = 'bfc_console.on_behalf_of';

    /**
     * This session's claims, or null when ANY of them is missing or
     * malformed. Null is a refusal, never a default: a delegated session
     * whose role cannot be read is a session with no role, and the guard
     * treats it exactly as expiry.
     */
    public static function claims(Session $session): ?DelegatedClaims
    {
        $displayName = $session->get(self::DISPLAY_NAME);
        $storedRole = $session->get(self::ROLE);
        $role = ConsoleRole::tryFrom(is_string($storedRole) ? $storedRole : '');
        $onBehalfOf = $session->get(self::ON_BEHALF_OF);

        if (! is_string($displayName) || $displayName === '' || ! $role instanceof ConsoleRole) {
            return null;
        }

        if ($onBehalfOf !== null && (! is_string($onBehalfOf) || $onBehalfOf === '')) {
            return null;
        }

        return new DelegatedClaims($displayName, $role, $onBehalfOf);
    }

    /**
     * Whether this session carries ANY console state. Used to tell an
     * orphaned marker — state whose principal no longer resolves — from a
     * session that was never delegated at all; the first is invalidated,
     * the second is simply not authenticated.
     */
    public static function hasState(Session $session): bool
    {
        foreach (self::keys() as $key) {
            if ($session->exists($key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every key a delegated session owns, for a caller that wants to
     * clear the Console's own state. Note that the enforcement path does
     * NOT use this: {@see ConsoleGuard} invalidates the WHOLE session
     * rather than forgetting these keys, and {@see EnsureConsoleSession}
     * says why.
     *
     * @return list<string>
     */
    public static function keys(): array
    {
        return [self::ASSERTION_ISSUED_AT, self::DISPLAY_NAME, self::ROLE, self::ON_BEHALF_OF];
    }
}
