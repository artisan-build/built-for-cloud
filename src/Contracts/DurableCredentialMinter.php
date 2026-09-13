<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\MintedDurableCredential;

/**
 * The seam through which claim-code exchange mints a unified credential.
 */
interface DurableCredentialMinter
{
    public function mint(string $name, string $scope): MintedDurableCredential;
}
