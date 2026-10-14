<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BfcClient\Actions\InstallHmacCredentialFromClaim as SharedInstallHmacCredentialFromClaim;
use ArtisanBuild\BfcClient\BoundCredentialScope;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BfcClient\InstalledHmacCredential;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\Hmac\UiHmacAppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Hmac\UnifiedHmacCredentialStore;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use SensitiveParameter;

/** @deprecated Use ArtisanBuild\BfcClient\Actions\InstallHmacCredentialFromClaim. */
final class InstallHmacCredentialFromClaim
{
    private readonly SharedInstallHmacCredentialFromClaim $shared;

    public function __construct(
        LifecycleEventRecorder $recorder,
        UiCredentialPurposes $purposes,
        HmacKeyring $keyring,
        HmacWriterBarrier $barrier,
    ) {
        $this->shared = new SharedInstallHmacCredentialFromClaim(
            new UiHmacAppPurposeRegistry($purposes),
            $keyring->implementation(),
            new UnifiedHmacCredentialStore(
                $recorder,
                app(ManagedAccountAccess::class),
                static fn (): HmacWriterBarrier => $barrier,
            ),
        );
    }

    public function __invoke(
        BoundCredentialScope $expectedScope,
        HmacCredentialIssuerClient $trustedIssuer,
        #[SensitiveParameter] string $claimCode,
    ): InstalledHmacCredential {
        return ($this->shared)(
            $expectedScope,
            $trustedIssuer,
            $claimCode,
        );
    }
}
