<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What a {@see Contracts\DurableCredentialMinter} hands back: the stored
 * row and the plaintext, still sealed in its carrier. The plaintext leaves
 * through {@see MintedSecret::reveal()} exactly once, at the response
 * boundary.
 *
 * The row is the unified `credentials` record. The exchange links the
 * claim code to `$token->getKey()`.
 */
final readonly class MintedDurableCredential
{
    public function __construct(
        public MintedSecret $secret,
        public Credential $token,
    ) {}
}
