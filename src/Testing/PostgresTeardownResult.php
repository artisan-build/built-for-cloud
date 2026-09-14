<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use JsonSerializable;

final readonly class PostgresTeardownResult implements JsonSerializable
{
    public function __construct(
        public bool $databaseAbsent,
        public bool $manifestAbsent,
        public bool $markerVerified,
        public bool $alreadyDropped,
        public string $verdict,
    ) {}

    /** @return array{database_absent: bool, manifest_absent: bool, marker_verified: bool, already_dropped: bool, verdict: string} */
    public function jsonSerialize(): array
    {
        return [
            'database_absent' => $this->databaseAbsent,
            'manifest_absent' => $this->manifestAbsent,
            'marker_verified' => $this->markerVerified,
            'already_dropped' => $this->alreadyDropped,
            'verdict' => $this->verdict,
        ];
    }
}
