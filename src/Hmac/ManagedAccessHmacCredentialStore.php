<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\Contracts\HmacCredentialStore;
use ArtisanBuild\BfcClient\StoredHmacCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use Carbon\CarbonImmutable;
use Closure;
use Throwable;

/** @internal Preserves the legacy verifier's injectable managed-access policy. */
final readonly class ManagedAccessHmacCredentialStore implements HmacCredentialStore
{
    public function __construct(
        private HmacCredentialStore $store,
        private ManagedAccountAccess $managedAccess,
    ) {}

    public function transaction(Closure $operation): mixed
    {
        return $this->store->transaction($operation);
    }

    public function find(string $credentialId, bool $lockForUpdate = false): ?StoredHmacCredential
    {
        return $this->store->find($credentialId, $lockForUpdate);
    }

    public function insertVerificationCopy(StoredHmacCredential $credential): void
    {
        $this->store->insertVerificationCopy($credential);
    }

    public function allowsAfterSignature(StoredHmacCredential $credential): bool
    {
        /** @var Credential|null $stored */
        $stored = Credential::query()->whereKey($credential->id)->first();

        return $stored instanceof Credential
            && hash_equals($stored->id, $credential->id)
            && $this->managedAccess->allowsCredential($stored);
    }

    public function stampUsage(string $credentialId, CarbonImmutable $usedAt): void
    {
        $this->store->stampUsage($credentialId, $usedAt);
    }

    public function hasKeyVersionOtherThan(string $writeVersion): bool
    {
        return $this->store->hasKeyVersionOtherThan($writeVersion);
    }

    public function isConcurrencyConflict(Throwable $failure): bool
    {
        return $this->store->isConcurrencyConflict($failure);
    }
}
