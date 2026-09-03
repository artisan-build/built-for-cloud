<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use RuntimeException;
use Throwable;

/**
 * `POST /bfc/console/enter` refused an entry for something the endpoint
 * decided rather than something the verifier did (Console PRD D12/D13):
 * purpose, the burn, the signed handoff state, or the return path.
 *
 * ONE exception class for every such refusal, carrying ONE uniform,
 * reason-free message — the same discipline {@see AssertionRefused}
 * holds for the token itself, for the same reason. The endpoint renders
 * both into one identical response, so a party feeding assertions at
 * this door cannot tell "replayed" from "expired" from "wrong audience"
 * from "tampered state".
 *
 * The machine-readable {@see ConsoleEntryRefusalReason} rides alongside
 * for the AUDIT RECORD, and `$assertionId` carries the mint identifier
 * when the token verified far enough to have one — which is exactly the
 * post-verification refusals, and never the ones the verifier decided.
 * The endpoint never guesses one.
 */
final class ConsoleEntryRefused extends RuntimeException
{
    /**
     * The single message every endpoint-side refusal carries.
     * Deliberately says nothing.
     */
    public const string MESSAGE = 'The console entry was refused.';

    public function __construct(
        public readonly ConsoleEntryRefusalReason $reason,
        public readonly ?string $assertionId = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct(self::MESSAGE, 0, $previous);
    }

    public static function because(
        ConsoleEntryRefusalReason $reason,
        ?string $assertionId = null,
        ?Throwable $previous = null,
    ): self {
        return new self($reason, $assertionId, $previous);
    }
}
