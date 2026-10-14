<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\BoundCredentialScope;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialStore;
use ArtisanBuild\BfcClient\Contracts\HmacVerificationConfiguration;
use ArtisanBuild\BfcClient\Exceptions\HmacVerificationFailed as SharedHmacVerificationFailed;
use ArtisanBuild\BfcClient\Hmac\HmacVerifier as SharedHmacVerifier;
use ArtisanBuild\BfcClient\Subject;
use ArtisanBuild\BfcClient\VerifiedHmacCredential;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use Illuminate\Database\Eloquent\ModelNotFoundException;

/**
 * Compatibility boundary over the client-owned verifier. Its shared replay
 * algorithm keeps the nonce entry beyond the inclusive timestamp interval,
 * so a nonce accepted once cannot be accepted again anywhere in its valid
 * window — boundary included.
 *
 * @deprecated Use ArtisanBuild\BfcClient\Hmac\HmacVerifier.
 */
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
        try {
            $verified = $this->shared->verify($subject, $header, $body, $audience);
        } catch (SharedHmacVerificationFailed $failure) {
            throw HmacVerificationFailed::fromShared($failure);
        }
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
        try {
            return $this->shared->verifyBound($scope, $header, $body);
        } catch (SharedHmacVerificationFailed $failure) {
            throw HmacVerificationFailed::fromShared($failure);
        }
    }
}
