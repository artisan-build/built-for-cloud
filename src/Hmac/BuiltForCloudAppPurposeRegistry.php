<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\Contracts\HmacAppPurposeRegistry;
use ArtisanBuild\BfcClient\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;

final readonly class BuiltForCloudAppPurposeRegistry implements HmacAppPurposeRegistry
{
    public function __construct(private AppPurposeRegistry $purposes) {}

    public function purpose(string $appPurpose): ?CredentialPurpose
    {
        return $this->purposes->purpose($appPurpose);
    }
}
