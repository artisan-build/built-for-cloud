<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use JsonSerializable;
use LogicException;

/** The authenticated client result; the secret remains in its one-use field. */
final readonly class ClaimedHmacCredential implements JsonSerializable
{
    private function __construct(
        public HmacCredentialTransfer $transfer,
        public ImportedHmacSecret $secret,
    ) {}

    /** @internal Constructs the client result parsed from an issuer response. */
    public static function fromIssuerResponse(HmacCredentialTransfer $transfer, ImportedHmacSecret $secret): self
    {
        return new self($transfer, $secret);
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('A claimed HMAC credential never serializes.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('A claimed HMAC credential never JSON-encodes.');
    }
}
