<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use RuntimeException;
use Throwable;

/**
 * A countersigning-key delivery was refused (Console PRD D12) — on the
 * claim surfaces, on the re-key route, or on the CLI verb alike.
 *
 * Deliberately NOT modelled on {@see AssertionRefused}, whose single
 * uniform message hides which check failed from a presenter who may be
 * probing. This is the opposite situation: the caller delivering a key
 * is the party that must fix a bad delivery, so the
 * {@see ConsoleKeyRefusal} reason and its server-authored message DO
 * travel back on every transport. What travels back is only ever the
 * enum's constant prose — the delivered key material is never echoed,
 * here or into an audit note.
 *
 * Both refusals are thrown by {@see ConsoleKeyring} as
 * {@see \InvalidArgumentException} and translated here; this class adds
 * no rule of its own, which is why the reasons match the ring's two
 * refusals exactly.
 */
final class ConsoleKeyRefused extends RuntimeException
{
    public function __construct(
        public readonly ConsoleKeyRefusal $reason,
        ?Throwable $previous = null,
    ) {
        parent::__construct($reason->message(), 0, $previous);
    }

    public static function because(ConsoleKeyRefusal $reason, ?Throwable $previous = null): self
    {
        return new self($reason, $previous);
    }
}
