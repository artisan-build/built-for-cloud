<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class SigningRootMacResult
{
    public function __construct(public string $keyId, public string $mac) {}
}
