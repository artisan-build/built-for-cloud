<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Carbon\CarbonImmutable;

/**
 * A VERIFIED console assertion (Console PRD D12/D8/D4): the delegated
 * identity one operator carries into one deployment for one entry.
 * Nothing constructs this except {@see AssertionVerifier} — holding an
 * instance means the Ed25519 signature verified under an active keyring
 * key, the issuer and audience matched, the clocks and the TTL bound
 * held, and every claim below survived shape and charset validation.
 *
 * The claim set is deliberately the SMALLEST that makes a delegated
 * session useful: who is acting, under what standing, on whose behalf,
 * where, and for how long. There is deliberately no email, no vendor
 * account id, no entitlement payload, no roster — an app receiving this
 * learns exactly enough to attribute an action and gate a policy, and
 * the vendor learns nothing at all about the app's own users (there is
 * no "Scalpels user x = app user y" mapping anywhere in this design).
 *
 * `$id` is the token's `jti`: the unique mint identifier PR4 BURNS
 * atomically at the enter endpoint, which is what makes an assertion
 * single-use. Verification deliberately does not burn it — this class is
 * the crypto/claims choke point, and the burn is a storage decision that
 * belongs to the endpoint that owns the transaction.
 */
final readonly class Assertion
{
    public function __construct(
        /** The one issuer this fleet trusts (D18) — the value that matched config. */
        public string $issuer,
        /** The issuer's opaque, stable identifier for the acting human. */
        public string $subject,
        /** The name the chrome renders for that human — bounded and charset-checked at the door. */
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
        /** The `jti` PR4 burns — one redemption per mint, ever. */
        public string $id,
    ) {}

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
     * "Jane (Acme Agency)" or plain "Jane". Both halves already passed
     * the verifier's charset and length bounds, so this string is safe
     * to render escape-by-construction (D11) without further trimming.
     */
    public function attribution(): string
    {
        return $this->onBehalfOf === null
            ? $this->displayName
            : sprintf('%s (%s)', $this->displayName, $this->onBehalfOf);
    }
}
