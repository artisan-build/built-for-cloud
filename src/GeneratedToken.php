<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class GeneratedToken
{
    public function __construct(
        public string $plaintext,
        public string $hash,
    ) {}
}
