<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What the rotate verb returns (PRD 1.7): a full {@see MintResult} for the
 * replacement — the same summary + sealed-carrier delivery shape the mint
 * verb produces, because a rotation IS a mint plus a supersession — and the
 * id of the row it superseded, so both transports can state the lineage
 * (old → new) the audit stream records.
 */
final readonly class RotationResult
{
    public function __construct(
        public MintResult $mint,
        public string $supersededId,
    ) {}
}
