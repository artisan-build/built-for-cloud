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
 *   `rotated_at` stamp;
 * - recovery is the old-row KILL, and it needs no authority beyond the
 *   rotation itself: re-invoking rotate on the stamped row performs the
 *   CUTOVER COMPLETION — retirement only, nothing minted, the lineage
 *   never forks — and revoke-by-id also works where that verb is
 *   authorized. The standing replacement can then be rotated for a
 *   fresh delivery, or revoked by id if unneeded.
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

    /**
     * The hmac activation's flavour of failure path B (PRD 1.21): the
     * pending→active cutover COMMITTED — the new key signs — but the
     * superseded old key could not be retired into its grace window, so
     * it verifies unbounded. Same recovery: re-invoking rotate on the
     * stamped row performs the cutover completion.
     */
    public static function activationRetirementFailed(string $supersededId, string $activatedId, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Activation cut signing over to credential %s, but could not retire superseded credential %s, '
                .'which still VERIFIES with no grace bound (listed with its rotated_at stamp). The activation '
                .'stands — the new key signs. Rotate %s again to complete the cutover (retirement only, nothing '
                .'minted), or revoke it by id.',
                $activatedId,
                $supersededId,
                $supersededId,
            ),
            $supersededId,
            $activatedId,
            $previous,
        );
    }

    public static function retirementFailed(string $supersededId, string $replacementId, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Rotation minted replacement %s but could not retire credential %s, which is STILL LIVE '
                .'(listed with its rotated_at stamp). Rotate %s again to complete the cutover (retirement only, '
                .'nothing minted), or revoke it by id; no secret was delivered, so rotate the standing '
                .'replacement %s for a fresh delivery, or revoke it by id if unused.',
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
