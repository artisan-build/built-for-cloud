<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use JsonSerializable;

final readonly class ConformanceFamilyReport implements JsonSerializable
{
    /**
     * @param  'applicable'|'not_applicable'  $applicability
     * @param  list<string>  $expected
     * @param  list<string>  $discovered
     * @param  list<string>  $violations
     * @param  list<string>  $limits
     */
    public function __construct(
        public string $applicability,
        public ?string $reason,
        public int $visited,
        public array $expected,
        public array $discovered,
        public array $violations,
        public array $limits,
    ) {}

    /** @return array{applicability: string, reason: string|null, visited: int, expected: list<string>, discovered: list<string>, violations: list<string>, limits: list<string>} */
    public function jsonSerialize(): array
    {
        return [
            'applicability' => $this->applicability,
            'reason' => $this->reason,
            'visited' => $this->visited,
            'expected' => $this->expected,
            'discovered' => $this->discovered,
            'violations' => $this->violations,
            'limits' => $this->limits,
        ];
    }
}
