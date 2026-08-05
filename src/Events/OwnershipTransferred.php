<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Events;

final class OwnershipTransferred
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly ?string $callbackUrl,
        public readonly string $secret,
        public readonly string $event,
        public readonly array $payload,
    ) {}
}
