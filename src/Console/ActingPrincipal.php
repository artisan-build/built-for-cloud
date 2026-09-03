<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * ONE resolved answer to "who is acting on this request, and under which
 * guard" (Console PRD D14) — plus the two facts a gate needs that the
 * acting principal alone does not carry: whether a delegated source is
 * PRESENT on this request at all, and whether a session was REFUSED.
 *
 * D14's rule is not "the delegated guard wins for authentication"; it is
 * that the delegated guard wins for the acting principal AND for every
 * piece of UI and attribution branching, from the SAME value. The two
 * halves live on this object precisely so they cannot be computed
 * separately and drift: the chrome (PR5) reads {@see $attribution} off
 * the same instance whose {@see $principal} the request acted as, and
 * the app-action audit stream (PR7) attributes from that same instance.
 * A layout that asked a guard directly, or an audit line that asked a
 * second time, is the failure mode D14 exists to forbid — one request,
 * one resolution.
 *
 * WHICH SESSION GUARD "WINS" IS DECIDED BY THE ROUTE, not by this class. A
 * console route carries `auth:bfc-console` ({@see Authenticate}), which
 * makes the delegated guard the one the request resolves through; on
 * such a route {@see $delegated} is true and `$request->user()`,
 * `Auth::user()` and {@see $principal} are the same object because they
 * all end at the same guard. On a route guarded by the app's own session
 * guard, the acting principal is the app's own user unless verified MCP
 * middleware published a delegated actor directly on this request. A
 * delegated session that is nonetheless live is reported by
 * {@see $delegatedActor}, never silently substituted.
 *
 * THE TWO DIRECTIONS ARE DELIBERATELY ASYMMETRIC, and the gates depend
 * on it:
 *
 *  - ADMISSION must be exact. {@see EnsureUserIsAdmin} admits a
 *    delegated operator only when {@see $delegated} is true and the console
 *    guard answered. A request assertion is delegated too, but carries no
 *    browser-session identity and is refused by that gate.
 *  - REFUSAL may be broad. {@see EnsureUserIsAuthenticated} refuses
 *    whenever {@see delegatedSessionPresent()} is true, whichever guard
 *    the route names. A surface that can only act as the authenticated
 *    LOCAL human has nothing to do while a delegated operator is in the
 *    same session, and saying no costs only convenience.
 *
 * A REFUSED delegated session is TERMINAL, whatever guard the route
 * uses: {@see $principal} is null and no package surface falls back to
 * the local user, because a request whose delegated session just died
 * must not quietly continue as somebody else. The guard has invalidated
 * that session's storage anyway.
 *
 * {@see ActingPrincipalResolver} builds it, once per request, and is the
 * only thing that should.
 */
final readonly class ActingPrincipal
{
    private function __construct(
        /** The guard that answered, or null when nobody is acting. */
        public ?string $guard,
        /**
         * Whether a delegated actor is THE ACTING PRINCIPAL — through the
         * route's console guard or a verified request assertion. Not merely
         * "a delegated source exists"; that is
         * {@see delegatedSessionPresent()}.
         */
        public bool $delegated,
        /** The acting principal itself, or null. */
        public ?Authenticatable $principal,
        /**
         * The DELEGATED attribution line ("Jane (Acme Agency)") as THIS
         * handoff carried it, or null for every
         * non-delegated resolution — a local session renders no chrome
         * (D11) and must produce no delegated attribution.
         *
         * **Issuer-supplied free text. Escape at every sink.**
         */
        public ?string $attribution,
        /**
         * The operator's display name ALONE, as this handoff carried it —
         * the same claim {@see $attribution}
         * composes, carried separately because the chrome (PR5) renders
         * the name and the agency into two different sinks and bounds
         * each on its own. It comes from request/session claims for the
         * reason {@see DelegatedClaims} gives: the actor row's
         * `last_handoff_display_name` is shared by every live session
         * for the same subject.
         *
         * **Issuer-supplied free text. Escape at every sink.**
         */
        public ?string $displayName,
        /** This handoff's delegated role (D8), or null when the acting principal is not delegated. */
        public ?ConsoleRole $role,
        /** The agency the operator acts for (D4), or null. */
        public ?string $onBehalfOf,
        /**
         * Why a delegated session was refused, or null when none was.
         * Non-null makes this resolution TERMINAL — see the class
         * docblock — and {@see EnsureConsoleSession} turns it into the
         * structured 401.
         */
        public ?ConsoleReentryReason $refusal,
        /**
         * The delegated actor this request carries through an assertion or
         * live session, whichever guard the route names. It is what lets a local-only gate refuse
         * rather than act as the wrong human, and what lets
         * {@see EnsureConsoleSession} answer before `auth:bfc-console`
         * has made the console guard the request's own.
         */
        public ?DelegatedActor $delegatedActor,
    ) {}

    /**
     * The delegated resolution: the console guard is the route's guard,
     * and this actor is what everything behind it will act as.
     *
     * The claims come from the SESSION, passed in explicitly — never
     * read off the actor row, which is shared by every live session for
     * the same subject and would let a later handoff rewrite this one's
     * role. {@see DelegatedClaims} carries the full reasoning.
     */
    public static function delegated(DelegatedActor $actor, DelegatedClaims $claims): self
    {
        return new self(
            guard: ConsoleGuardConfiguration::GUARD,
            delegated: true,
            principal: $actor,
            attribution: $claims->attribution(),
            displayName: $claims->displayName,
            role: $claims->role,
            onBehalfOf: $claims->onBehalfOf,
            refusal: null,
            delegatedActor: $actor,
        );
    }

    /** A delegated assertion acting for this request without a session guard. */
    public static function delegatedRequest(DelegatedActor $actor, DelegatedClaims $claims): self
    {
        return new self(
            guard: null,
            delegated: true,
            principal: $actor,
            attribution: $claims->attribution(),
            displayName: $claims->displayName,
            role: $claims->role,
            onBehalfOf: $claims->onBehalfOf,
            refusal: null,
            delegatedActor: $actor,
        );
    }

    public static function local(string $guard, Authenticatable $user, ?DelegatedActor $delegatedActor = null): self
    {
        return new self(
            guard: $guard,
            delegated: false,
            principal: $user,
            attribution: null,
            displayName: null,
            role: null,
            onBehalfOf: null,
            refusal: null,
            delegatedActor: $delegatedActor,
        );
    }

    /**
     * A delegated session was refused. Nobody is acting, and nobody may
     * be substituted: this state exists so that "the console session
     * died" can never be read as "fall back to whoever else is logged
     * in".
     */
    public static function refused(ConsoleReentryReason $reason): self
    {
        return new self(
            guard: ConsoleGuardConfiguration::GUARD,
            delegated: false,
            principal: null,
            attribution: null,
            displayName: null,
            role: null,
            onBehalfOf: null,
            refusal: $reason,
            delegatedActor: null,
        );
    }

    public static function none(?DelegatedActor $delegatedActor = null): self
    {
        return new self(
            guard: null,
            delegated: false,
            principal: null,
            attribution: null,
            displayName: null,
            role: null,
            onBehalfOf: null,
            refusal: null,
            delegatedActor: $delegatedActor,
        );
    }

    /**
     * The acting principal's identifier — type-qualified
     * (`bfc-console:{id}`) for a delegated actor, the host app's own id
     * for a local user. The qualifier is why a caller can key on this
     * without first asking which kind of principal it holds.
     */
    public function identifier(): int|string|null
    {
        $identifier = $this->principal?->getAuthIdentifier();

        // The contract's return type is `mixed`; anything that is not a
        // scalar id is no id at all here, rather than something a caller
        // has to re-check.
        return is_int($identifier) || is_string($identifier) ? $identifier : null;
    }

    public function check(): bool
    {
        return $this->principal !== null;
    }

    /**
     * Whether a delegated session was refused on this request. A caller
     * that treats this as "not logged in" and continues is the bug the
     * state exists to prevent — the correct answers are re-entry (the
     * structured 401) or an outright refusal.
     */
    public function wasRefused(): bool
    {
        return $this->refusal instanceof ConsoleReentryReason;
    }

    /**
     * Whether this request carries a delegated source AT ALL — a request
     * assertion, or a delegated session live or just refused. This retained
     * method name is public API; it now answers the broad question a
     * local-only surface refuses on.
     */
    public function delegatedSessionPresent(): bool
    {
        return $this->delegatedActor instanceof DelegatedActor || $this->wasRefused();
    }
}
