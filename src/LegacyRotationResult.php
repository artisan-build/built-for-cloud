<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What {@see TokenRegistry::rotateById()} returns: the standing
 * replacement and the supersession lineage. On the normal path `token` is
 * the row minted from the caller's hash; on the `completedCutover` path
 * the verb was re-invoked on a stamped old row whose live successor
 * already stood, so NOTHING was minted — `token` is that successor, and
 * the caller's hash was never stored (a transport must not present its
 * pre-generated plaintext as a credential).
 */
final readonly class LegacyRotationResult
{
    public function __construct(
        public ApiToken $token,
        public string $supersededId,
        public bool $completedCutover = false,
    ) {}
}
