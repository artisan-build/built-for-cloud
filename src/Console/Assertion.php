<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Carbon\CarbonImmutable;

/**
 * The claims of a console assertion that {@see AssertionVerifier} has
 * checked (Console PRD D12/D8/D4): the delegated identity one operator
 * carries into one deployment for one entry.
 *
 * The constructor is private and the only way in is
 * {@see fromVerifiedClaims()}, whose name is the warning: PHP cannot
 * restrict a static factory to one caller, so this type is NOT proof of
 * provenance. It carries claims the verifier checked when the verifier
 * built it, and building one anywhere else is a bug — the delegated
 * session PR3 opens and the ADMIN standing PR4 grants both read this
 * object, so an instance conjured without a token is an unauthenticated
 * admin. If you are reaching for the factory outside a verifier, stop.
 *
 * The claim set is deliberately the SMALLEST that makes a delegated
 * session useful: who is acting, under what standing, on whose behalf,
 * where, and for how long. There is deliberately no email, no vendor
 * account id, no entitlement payload, no roster — an app receiving this
 * learns exactly enough to attribute an action and gate a policy, and
 * the vendor learns nothing at all about the app's own users (there is
 * no "Scalpels user x = app user y" mapping anywhere in this design).
 *
 * `$id` is the token's `jti`: the unique mint identifier the
 * redeeming door BURNS atomically — the enter endpoint inside its
 * session-minting transaction, `AuthenticateMcp` inside its own —
 * which is what makes an assertion single-use. Verification
 * deliberately does not burn it — the verifier is the crypto/claims
 * choke point, and the burn is a storage decision that belongs to the
 * door that owns the transaction.
 *
 * **The display claims are NOT sanitized HTML.** They are bounded in
 * length and free of control characters, and that is all — see
 * {@see attribution()}.
 */
final readonly class Assertion
{
    private function __construct(
        /** The one issuer this fleet trusts (D18) — the value that matched config. */
        public string $issuer,
        /** The issuer's opaque, stable identifier for the acting human. */
        public string $subject,
        /** The name the chrome renders for that human — length- and control-character-bounded, nothing more. */
        public string $displayName,
        /** The two-value contract standing (D8). */
        public ConsoleRole $role,
        /** The agency the operator acts for (D4), or null for a direct operator. */
        public ?string $onBehalfOf,
        /** THIS deployment's identity: an assertion for anywhere else is worthless here (D12). */
        public string $audience,
        public CarbonImmutable $issuedAt,
        public CarbonImmutable $expiresAt,
        /** The keyring key that verified the signature. */
        public string $keyId,
        /** The `jti` the redeeming door burns — one redemption per mint, ever. */
        public string $id,
        /**
         * The sha256 hex digest of the SIGNED HANDOFF STATE (D13), or
         * null when the mint carried none.
         *
         * This is what makes the return path a signed state rather than
         * a request field: the state travels beside the token, its
         * digest travels INSIDE it, and the enter endpoint accepts a
         * state only when the two agree. The app holds nothing but
         * PUBLIC keys, so an Ed25519 signature over this digest is the
         * only thing it can verify the issuer produced — and an
         * OAuth-style state the APP planted is impossible here, because
         * the handoff POST is cross-site and `SameSite=Lax` means the
         * browser sends no cookie with it. See
         * {@see ConsoleEntryState}, which states what that does and does
         * not buy.
         *
         * Null is a well-formed mint that named no state. The VERIFIER
         * does not require one — its job is that claims are well-formed
         * — and the ENTER ENDPOINT does, because entry is the flow the
         * decision governs.
         */
        public ?string $stateDigest = null,
        /** The door this mint is for, or null for a legacy console-entry mint during the compatibility window. */
        public ?AssertionPurpose $purpose = null,
    ) {}

    /**
     * Build the assertion from claims a verifier has ALREADY checked.
     *
     * Named for what it demands rather than for what it does, because
     * the language cannot enforce the demand: every caller is asserting
     * that the Ed25519 signature verified under an active keyring key,
     * that issuer and audience matched, and that the clocks, the TTL
     * bound and the claim shapes all held. {@see AssertionVerifier} is
     * the only caller in this package and should remain the only caller
     * anywhere.
     */
    public static function fromVerifiedClaims(
        string $issuer,
        string $subject,
        string $displayName,
        ConsoleRole $role,
        ?string $onBehalfOf,
        string $audience,
        CarbonImmutable $issuedAt,
        CarbonImmutable $expiresAt,
        string $keyId,
        string $id,
        ?string $stateDigest = null,
        ?AssertionPurpose $purpose = null,
    ): self {
        return new self(
            issuer: $issuer,
            subject: $subject,
            displayName: $displayName,
            role: $role,
            onBehalfOf: $onBehalfOf,
            audience: $audience,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            keyId: $keyId,
            id: $id,
            stateDigest: $stateDigest,
            purpose: $purpose,
        );
    }

    /**
     * Whether the operator carries admin standing. A convenience over
     * the enum so calling code reads as intent rather than comparison;
     * apps still map the role onto their OWN policies (D8) rather than
     * treating this as an authorization answer.
     */
    public function isAdmin(): bool
    {
        return $this->role === ConsoleRole::Admin;
    }

    /**
     * The attribution line the audit stream and the chrome both want:
     * "Jane (Acme Agency)" or plain "Jane".
     *
     * **ESCAPE THIS AT EVERY SINK.** Both halves are bounded in length
     * and rejected if they carry control characters — and that is the
     * whole of it. A display name is issuer-supplied free text that may
     * legitimately contain apostrophes, accents, `&` and `<`, and this
     * string carries them through verbatim: bounding a string is not
     * sanitizing it, and `<img src=x onerror=…>` passes every check the
     * verifier makes. The chrome that renders this (PR5) is a
     * PRIVILEGED admin surface, so it must escape for its context —
     * HTML text, attribute, JS, or URL — exactly as it would for any
     * other user-supplied string. D11's escape-by-construction promise
     * is about that rendering layer; the bounds here are the verify-side
     * half that keeps the string a single line of finite length, not a
     * licence to interpolate it raw.
     */
    public function attribution(): string
    {
        return $this->onBehalfOf === null
            ? $this->displayName
            : sprintf('%s (%s)', $this->displayName, $this->onBehalfOf);
    }
}
