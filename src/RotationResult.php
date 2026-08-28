<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What the rotate verb returns (PRD 1.7): a full {@see MintResult} for the
 * replacement — the same summary + sealed-carrier delivery shape the mint
 * verb produces, because a rotation IS a mint plus a supersession — and the
 * id of the row it superseded, so both transports can state the lineage
 * (old → new) the audit stream records.
 *
 * `completedCutover` marks the retirement-only path: the verb was
 * re-invoked on a stamped old row whose live successor already stood, so
 * NOTHING was minted — `mint` summarizes the standing successor, its
 * delivery shape is `none`, and no secret exists to reveal.
 */
final readonly class RotationResult
{
    public function __construct(
        public MintResult $mint,
        public string $supersededId,
        public bool $completedCutover = false,
    ) {}
}
