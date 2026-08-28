<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\MintedDurableCredential;

/**
 * The seam between the claim-code primitive and wherever durable
 * credentials live. Exchange mints through this interface only, so a later
 * release can redirect minting from `api_tokens` to the unified store
 * without reworking the primitive.
 */
interface DurableCredentialMinter
{
    public function mint(string $name, string $scope): MintedDurableCredential;
}
