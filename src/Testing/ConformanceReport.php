<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use JsonSerializable;

final readonly class ConformanceReport implements JsonSerializable
{
    /** @param array<string, ConformanceFamilyReport> $families */
    public function __construct(
        public string $consumer,
        public int $packageApiVersion,
        public bool $passed,
        public array $families,
    ) {}

    /** @return array{schema_version: 1, consumer: string, package_api_version: int, passed: bool, families: array<string, ConformanceFamilyReport>} */
    public function jsonSerialize(): array
    {
        return [
            'schema_version' => 1,
            'consumer' => $this->consumer,
            'package_api_version' => $this->packageApiVersion,
            'passed' => $this->passed,
            'families' => $this->families,
        ];
    }

    public function canonicalJson(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
