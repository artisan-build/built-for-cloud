<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class DeviceAuthorizationStart
{
    public function __construct(
        public string $authorizationId,
        public MintedSecret $deviceCode,
        public MintedSecret $userCode,
        public MintedSecret $browserNonce,
        public string $verificationUri,
        public int $expiresIn,
        public int $interval,
    ) {}
}
