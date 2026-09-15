<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonImmutable;
use JsonSerializable;
use LogicException;

/** The exact non-portable facts returned by one bound HMAC claim. */
final readonly class HmacCredentialTransfer implements JsonSerializable
{
    private function __construct(
        public string $issuerCredentialId,
        public BoundCredentialScope $scope,
        public string $algorithm,
        public ?CarbonImmutable $credentialExpiresAt,
        public int $deliveryGeneration,
        public string $deliveryFingerprint,
        public ?string $predecessorCredentialId,
        public CredentialStatus $sourceStatus,
        public CarbonImmutable $deliveredAt,
        public CarbonImmutable $transferExpiresAt,
    ) {}

    /** @internal Called only by the package issuer-response parser. */
    public static function fromIssuerResponse(
        string $issuerCredentialId,
        BoundCredentialScope $scope,
        string $algorithm,
        ?CarbonImmutable $credentialExpiresAt,
        int $deliveryGeneration,
        string $deliveryFingerprint,
        ?string $predecessorCredentialId,
        CredentialStatus $sourceStatus,
        CarbonImmutable $deliveredAt,
        CarbonImmutable $transferExpiresAt,
    ): self {
        return new self(
            $issuerCredentialId,
            $scope,
            $algorithm,
            $credentialExpiresAt,
            $deliveryGeneration,
            $deliveryFingerprint,
            $predecessorCredentialId,
            $sourceStatus,
            $deliveredAt,
            $transferExpiresAt,
        );
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('An HMAC credential transfer never serializes.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('An HMAC credential transfer never JSON-encodes.');
    }
}
