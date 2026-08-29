<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/**
 * The claims ONE handoff carried, bound to ONE session (Console PRD D8:
 * role and display claims are per-mint and never cached beyond the
 * session).
 *
 * This type exists because the alternative — reading them off the shadow
 * actor row — is a privilege escalation. That row is shared by every live
 * session for the same subject, so a later handoff arriving as `admin`
 * would retroactively promote a session that entered as `member`, and
 * attribute it to whatever agency the newer handoff named. The claims a
 * request acts under therefore live in that request's own session and
 * nowhere else; the row keeps only a `last_handoff_*` copy, named so that
 * reading it for authorization looks as wrong as it is.
 *
 * The set is atomic: {@see ConsoleSession::claims()} returns an instance
 * or null, never a partially populated one, because a session carrying a
 * role but no display name is a session whose claims cannot be trusted.
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
        /** The name the chrome renders — bounded, control-character-free, NOT escaped. */
        public string $displayName,
        /** The two-value contract standing this session acts under (D8). */
        public ConsoleRole $role,
        /** The agency the operator acts for (D4), or null for a direct operator. */
        public ?string $onBehalfOf,
    ) {}

    public static function fromAssertion(Assertion $assertion): self
    {
        return new self(
            displayName: $assertion->displayName,
            role: $assertion->role,
            onBehalfOf: $assertion->onBehalfOf,
        );
    }

    /**
     * The attribution line the chrome (PR5) and the app-action audit
     * stream (PR7) render: "Jane (Acme Agency)" or plain "Jane".
     *
     * **ESCAPE THIS AT EVERY SINK.**
     */
    public function attribution(): string
    {
        return $this->onBehalfOf === null
            ? $this->displayName
            : sprintf('%s (%s)', $this->displayName, $this->onBehalfOf);
    }

    public function isAdmin(): bool
    {
        return $this->role === ConsoleRole::Admin;
    }
}
