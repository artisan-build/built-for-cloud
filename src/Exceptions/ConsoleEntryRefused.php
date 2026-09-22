<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use RuntimeException;
use Throwable;

/**
 * A delegated-assertion DOOR refused a presentation for something the
 * door decided rather than something the verifier did (Console PRD
 * D12/D13): purpose, the burn, or containment. The state and
 * return-path cases survive from the retired delegated-entry door,
 * which was the only door that could produce them.
 *
 * Thrown by the MCP authentication middleware, which renders its
 * uniform 401 and audits the reason code. ONE door, one response
 * translation, one bounded vocabulary. The Console-prefixed NAME
 * predates the door's narrowing to MCP and is kept for stability.
 *
 * ONE exception class for every such refusal, carrying ONE uniform,
 * reason-free message — the same discipline {@see AssertionRefused}
 * holds for the token itself, for the same reason. The door renders
 * everything into its one identical response, so a party feeding
 * assertions at it cannot tell "replayed" from "expired" from
 * "wrong audience" from "tampered state".
 *
 * The machine-readable {@see ConsoleEntryRefusalReason} rides alongside
 * for the AUDIT RECORD, and `$assertionId` carries the mint identifier
 * when the token verified far enough to have one — which is exactly the
 * post-verification refusals, and never the ones the verifier decided.
 * The door never guesses one.
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
