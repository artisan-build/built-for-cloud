<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\Contracts\HmacAppPurposeRegistry;
use ArtisanBuild\BfcClient\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;

final readonly class UiHmacAppPurposeRegistry implements HmacAppPurposeRegistry
{
    public function __construct(private UiCredentialPurposes $purposes) {}

    public function purpose(string $appPurpose): CredentialPurpose
    {
        return $this->purposes->purposeForSubmission($appPurpose);
    }
}
