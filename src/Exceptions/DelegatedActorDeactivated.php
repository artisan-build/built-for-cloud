<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * A valid assertion arrived for a delegated actor this deployment has
 * DEACTIVATED (offboarding, PRD 1.15's shape applied to delegated
 * identity).
 *
 * It is a refusal rather than a silent no-op because the two are not the
 * same thing: the issuer still vouches for this human — the signature,
 * the audience and the clocks all held — and the local decision to
 * contain them is what stops the request.
 * `AuthenticateMcp` throws this BEFORE anything is published, inside the
 * transaction that burns the mint, so a deactivated actor cannot be the
 * principal for even the one request that presented the assertion.
 *
 * The handoff is still RECORDED before this throws, and COMMITTED
 * separately from the decision that refuses it: the row's
 * `last_handoff_*` copy is refreshed, so an operator looking at a
 * contained actor can see that entry was attempted and with what claims.
 * A single transaction would roll the record back along with the
 * refusal, and the attempt would leave no trace.
 */
final class DelegatedActorDeactivated extends RuntimeException
{
    public static function cannotEnter(): self
    {
        return new self('This delegated console actor has been deactivated in this deployment and may not enter.');
    }
}
