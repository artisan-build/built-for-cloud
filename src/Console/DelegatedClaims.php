<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;

/**
 * The claims ONE handoff carried, bound to ONE request (Console PRD D8:
 * role and display claims are per-mint and never read from shared actor
 * storage).
 *
 * This type exists because the alternative — reading them off the shadow
 * actor row — is a privilege escalation. That row is shared by every
 * request for the same subject, so a later handoff arriving as `admin`
 * would retroactively promote a request that arrived as `member`, and
 * attribute it to whatever agency the newer handoff named. The claims a
 * request acts under therefore live in the request; an MCP request
 * builds them from its just-verified assertion. The row keeps only a
 * `last_handoff_*` copy, named so reading it for authorization looks
 * wrong.
 *
 * The set is atomic: a principal is published carrying every claim or
 * none, never a partially populated set, because a request carrying a
 * role but no display name is a request whose claims cannot be trusted.
 *
 * A CONVENIENCE WAS DELETED FROM HERE, for one reason.
 *
 * `isAdmin()` sat unreferenced while the single place that decides
 * administrative standing — {@see EnsureUserIsAdmin} — compared the enum
 * directly. An unreferenced predicate on a claims object is an
 * invitation to a second, divergent notion of "is admin", and the two
 * would drift the first time one of them grew a condition. Read
 * {@see $role} and compare it where the decision is made.
 *
 * **THE DISPLAY CLAIMS ARE NOT SANITIZED.** `displayName` and
 * `onBehalfOf` are issuer-supplied free text that the verifier bounded in
 * length and rejected for control characters — nothing more. They may
 * legitimately contain `<`, `&` and quotes, and this object passes them
 * through verbatim, {@see attribution()} included. Escape at every sink.
 */
final readonly class DelegatedClaims
{
    public function __construct(
        /** The name a rendering surface shows — bounded, control-character-free, NOT escaped. */
        public string $displayName,
        /** The two-value contract standing this request acts under (D8). */
        public ConsoleRole $role,
        /** The agency the operator acts for (D4), or null for a direct operator. */
        public ?string $onBehalfOf,
    ) {}

    /**
     * The attribution line the app-action audit
     * stream renders: "Jane (Acme Agency)" or plain "Jane".
     *
     * **ESCAPE THIS AT EVERY SINK.**
     */
    public function attribution(): string
    {
        return $this->onBehalfOf === null
            ? $this->displayName
            : sprintf('%s (%s)', $this->displayName, $this->onBehalfOf);
    }
}
