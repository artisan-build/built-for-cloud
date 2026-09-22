<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * ONE resolved answer to "who is acting on this request, and under which
 * guard" — plus the fact a gate needs that the acting principal alone
 * does not carry: whether a delegated source is PRESENT on this request
 * at all.
 *
 * The rule is not "the delegated guard wins for authentication"; it is
 * that every piece of UI and attribution branching reads the SAME value.
 * The two halves live on this object precisely so they cannot be computed
 * separately and drift: the app-action audit stream attributes from the
 * same instance whose {@see $principal} the request acted as. An audit
 * line that asked a second time is the failure mode this value exists to
 * forbid — one request, one resolution.
 *
 * WHICH GUARD "WINS" IS DECIDED BY THE ROUTE, not by this class. On a
 * route guarded by the app's own session guard, the acting principal is
 * the app's own user unless verified MCP middleware published a
 * delegated actor directly on this request.
 *
 * THE TWO DIRECTIONS ARE DELIBERATELY ASYMMETRIC, and the gates depend
 * on it:
 *
 *  - ADMISSION must be exact. {@see EnsureUserIsAdmin} never admits a
 *    delegated operator: a request assertion carries no browser-session
 *    identity and is refused by that gate.
 *  - REFUSAL may be broad. {@see EnsureUserIsAuthenticated} refuses
 *    whenever {@see delegatedSessionPresent()} is true, whichever guard
 *    the route names. A surface that can only act as the authenticated
 *    LOCAL human has nothing to do while a delegated actor is the one
 *    on the request, and saying no costs only convenience.
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
         * Whether a delegated actor is THE ACTING PRINCIPAL — a verified
         * request assertion. Not merely "a delegated source exists";
         * that is {@see delegatedSessionPresent()}.
         */
        public bool $delegated,
        /** The acting principal itself, or null. */
        public ?Authenticatable $principal,
        /**
         * The DELEGATED attribution line ("Jane (Acme Agency)") as THIS
         * handoff carried it, or null for every non-delegated
         * resolution — a local session renders no chrome and must
         * produce no delegated attribution.
         *
         * **Issuer-supplied free text. Escape at every sink.**
         */
        public ?string $attribution,
        /**
         * The operator's display name ALONE, as this handoff carried it —
         * the same claim {@see $attribution} composes, carried
         * separately because a surface may render the name and the
         * agency into two different sinks and bound each on its own. It
         * comes from request claims for the reason
         * {@see DelegatedClaims} gives: the actor row's
         * `last_handoff_display_name` is shared by every request for
         * the same subject.
         *
         * **Issuer-supplied free text. Escape at every sink.**
         */
        public ?string $displayName,
        /** This handoff's delegated role, or null when the acting principal is not delegated. */
        public ?ConsoleRole $role,
        /** The agency the operator acts for, or null. */
        public ?string $onBehalfOf,
        /**
         * The delegated actor this request carries through a verified
         * assertion, whichever guard the route names. It is what lets a
         * local-only gate refuse rather than act as the wrong human.
         */
        public ?DelegatedActor $delegatedActor,
    ) {}

    /**
     * A delegated assertion acting for this request without a session guard.
     */
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
            delegatedActor: $actor,
        );
    }

    public static function local(string $guard, Authenticatable $user): self
    {
        return new self(
            guard: $guard,
            delegated: false,
            principal: $user,
            attribution: null,
            displayName: null,
            role: null,
            onBehalfOf: null,
            delegatedActor: null,
        );
    }

    public static function none(): self
    {
        return new self(
            guard: null,
            delegated: false,
            principal: null,
            attribution: null,
            displayName: null,
            role: null,
            onBehalfOf: null,
            delegatedActor: null,
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
     * Whether this request carries a delegated source AT ALL — a
     * verified request assertion published on it. This retained method
     * name is public API; it answers the broad question a local-only
     * surface refuses on.
     */
    public function delegatedSessionPresent(): bool
    {
        return $this->delegatedActor instanceof DelegatedActor;
    }
}
