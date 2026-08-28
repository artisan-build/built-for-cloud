<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Subject;
use RuntimeException;

/**
 * The signer cannot sign for a subject. The load-bearing case (locked
 * AC 9): a subject whose only keys are PENDING signs nothing — a pending
 * key is inert until the activation verb cuts it over (SEC-V3-01) — and
 * the error says so explicitly instead of leaving "no key" ambiguous.
 * Never carries key material.
 */
final class HmacSigningRefused extends RuntimeException
{
    public static function noActiveKey(Subject $subject, int $pendingKeys): self
    {
        $pendingClause = $pendingKeys > 0
            ? sprintf(
                ' %d pending key(s) exist for it — a pending key signs nothing until activated (bfc:credential:activate).',
                $pendingKeys,
            )
            : ' Mint an hmac credential for it first.';

        return new self(sprintf(
            'No ACTIVE hmac signing key exists for subject %s:%s.%s',
            $subject->type->value,
            $subject->ref,
            $pendingClause,
        ));
    }
}
