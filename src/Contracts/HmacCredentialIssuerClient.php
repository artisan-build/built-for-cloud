<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\SensitiveString;

/** The mandatory trusted provisioning channel for cross-store HMAC material. */
interface HmacCredentialIssuerClient
{
    public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential;

    public function activate(
        BoundCredentialScope $expectedScope,
        ?string $predecessorId,
        string $replacementId,
        string $deliveryFingerprint,
    ): IssuerHmacCutoverReceipt;

    public function cutoverStatus(
        BoundCredentialScope $expectedScope,
        ?string $predecessorId,
        string $replacementId,
    ): IssuerHmacCutoverReceipt;
}
