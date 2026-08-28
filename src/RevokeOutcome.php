<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What the unified revoke verb found: no such row ever existed, the row
 * died by this call (one death, one audit event), or it was already dead
 * (idempotent no-op — no second audit event for the same death).
 */
enum RevokeOutcome
{
    case NotFound;
    case Revoked;
    case AlreadyDead;
}
