<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What one offboard invocation did (PRD 1.15). `acknowledged` marks the
 * integration path's uniform answer — the caller learns the event was
 * decided, never what the decision was (SEC-V3-05's uniformity, shared
 * with the invite verb). On the direct path, `applied` is false when the
 * subject was ALREADY contained (the idempotent no-op: same result
 * shape, zero counts, no new audit rows).
 */
final readonly class OffboardResult
{
    public function __construct(
        public bool $acknowledged,
        public bool $applied,
        public int $revokedCredentials = 0,
        public int $consumedCodes = 0,
        public int $canceledInvitations = 0,
        public int $deletedResetTokens = 0,
        public int $deletedSessions = 0,
        public int $deactivatedUsers = 0,
    ) {}

    public static function acknowledged(): self
    {
        return new self(acknowledged: true, applied: false);
    }
}
