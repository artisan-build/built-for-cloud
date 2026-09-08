<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class AuthorityState
{
    private function __construct(
        public ?AuthorityMode $mode,
        public int $generation,
    ) {}

    public static function fromRaw(string $mode, int $generation): self
    {
        return new self(AuthorityMode::tryFrom($mode), $generation);
    }

    public function isValid(): bool
    {
        return $this->mode !== null && $this->generation >= 1;
    }
}
