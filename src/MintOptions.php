<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

/**
 * What a caller may choose when minting into the unified store (PRD 1.6).
 *
 * Everything here is CALLER-CHOSEN and optional. In particular `expiresAt`
 * has NO default, deliberately (PRD 1.3, DO-NOT-BUILD: TTL defaults on
 * durables): revocation-on-event, not expiry, is the intended end of a
 * durable's life, and a package that quietly stamps one would be nudging.
 *
 * `codeTtlSeconds` applies only to the `asymmetric` kind, whose delivery is
 * an enrollment code minted through the claim primitive — the code is the
 * thing with the short, REQUIRED lifetime (60s–7d, PRD 1.1), never the
 * credential.
 */
final readonly class MintOptions
{
    /**
     * @param  list<string>|null  $abilities
     */
    public function __construct(
        public CredentialKind $kind = CredentialKind::Bearer,
        public ?string $name = null,
        public ?array $abilities = null,
        public ?CarbonInterface $expiresAt = null,
        public ?string $userId = null,
        public ?int $codeTtlSeconds = null,
    ) {}
}
