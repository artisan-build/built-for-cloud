<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What a {@see Contracts\DurableCredentialMinter} hands back: the stored
 * row and the plaintext, still sealed in its carrier. The plaintext leaves
 * through {@see MintedSecret::reveal()} exactly once, at the response
 * boundary.
 *
 * The row is whichever store the seam targeted: `api_tokens` (the
 * default) or the unified `credentials` store (a declaration opting in,
 * PRD 1.0). Both are uuid-keyed models; the exchange links the claim code
 * to `$token->getKey()` either way.
 */
final readonly class MintedDurableCredential
{
    public function __construct(
        public MintedSecret $secret,
        public ApiToken|Credential $token,
    ) {}
}
