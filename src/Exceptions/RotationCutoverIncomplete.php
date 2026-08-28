<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Failure path B of the rotate verb (PRD 1.7, D6 point 5): the replacement
 * was minted and committed, but retiring the old row — the expiry-set at
 * cutover — failed. The stated cleanup, named IN the error so the caller is
 * never guessing:
 *
 * - the NEW credential stands (active, correctly scoped, killable by id);
 *   its secret was NOT delivered — the sealed carrier is discarded, so
 *   nothing leaked and nothing usable is orphaned;
 * - the OLD row is still live, visible in the listing with its
 *   `rotated_at` stamp, and revoke-by-id can always kill it (the
 *   anomaly-repair semantics of the by-id revoke verbs);
 * - recovery is the old-row KILL, never a re-rotation: the stamped row
 *   refuses to rotate again (lineage never forks), and the standing
 *   replacement is the rotatable row — rotate IT for a fresh delivery,
 *   or revoke it by id if unneeded.
 */
final class RotationCutoverIncomplete extends RuntimeException
{
    private function __construct(
        string $message,
        public readonly string $supersededId,
        public readonly string $replacementId,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function retirementFailed(string $supersededId, string $replacementId, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Rotation minted replacement %s but could not retire credential %s, which is STILL LIVE '
                .'(listed with its rotated_at stamp). Revoke %s by id to complete the cutover; no secret was '
                .'delivered, so rotate the standing replacement %s for a fresh delivery, or revoke it by id if unused.',
                $replacementId,
                $supersededId,
                $supersededId,
                $replacementId,
            ),
            $supersededId,
            $replacementId,
            $previous,
        );
    }
}
