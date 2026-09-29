<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use RuntimeException;

/** A bounded, value-free two-phase protocol refusal. */
final class TwoPhaseConfirmationRefused extends RuntimeException
{
    public const string EXPIRED = 'confirmation_expired';

    public const string INVALID = 'confirmation_invalid';

    public const string MISMATCHED = 'confirmation_mismatched';

    public const string SPENT = 'confirmation_spent';

    public const string UNAVAILABLE = 'confirmation_unavailable';

    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
