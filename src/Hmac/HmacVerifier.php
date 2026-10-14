<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\BoundCredentialScope;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialStore;
use ArtisanBuild\BfcClient\Contracts\HmacVerificationConfiguration;
use ArtisanBuild\BfcClient\Hmac\HmacVerifier as SharedHmacVerifier;
use ArtisanBuild\BfcClient\Subject;
use ArtisanBuild\BfcClient\VerifiedHmacCredential;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use Illuminate\Database\Eloquent\ModelNotFoundException;

/** @deprecated Use ArtisanBuild\BfcClient\Hmac\HmacVerifier. */
final class HmacVerifier
{
    private readonly SharedHmacVerifier $shared;

    public function __construct(
        HmacKeyring $keyring,
        ?ManagedAccountAccess $managedAccess = null,
        ?AppPurposeRegistry $appPurposes = null,
    ) {
        $store = app(HmacCredentialStore::class);

        if ($managedAccess !== null) {
            $store = new ManagedAccessHmacCredentialStore($store, $managedAccess);
        }

        $this->shared = new SharedHmacVerifier(
            $keyring->implementation(),
            new BuiltForCloudAppPurposeRegistry($appPurposes ?? app(AppPurposeRegistry::class)),
            $store,
            app(HmacVerificationConfiguration::class),
        );
    }

    public function verify(
        Subject $subject,
        string $header,
        string $body,
        ?string $audience = null,
    ): Credential {
        $verified = $this->shared->verify($subject, $header, $body, $audience);
        /** @var Credential|null $credential */
        $credential = Credential::query()->whereKey($verified->credentialId)->first();

        if (! $credential instanceof Credential || ! hash_equals($credential->id, $verified->credentialId)) {
            throw (new ModelNotFoundException)->setModel(Credential::class, [$verified->credentialId]);
        }

        return $credential;
    }

    public function verifyBound(
        BoundCredentialScope $scope,
        string $header,
        string $body,
    ): VerifiedHmacCredential {
        return $this->shared->verifyBound($scope, $header, $body);
    }
}
