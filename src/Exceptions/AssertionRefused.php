<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use RuntimeException;
use Throwable;

/**
 * A console assertion did not verify (Console PRD D12). ONE exception
 * class for every refusal, carrying ONE uniform, reason-free message:
 * {@see self::MESSAGE}. Whoever presented the token learns only that it
 * was refused — never whether the signature was wrong, the key unknown,
 * the audience another deployment's, or the clock past `exp`. That
 * uniformity is the anti-oracle property {@see AssertionVerifier} exists
 * to hold: an attacker probing the enter endpoint with a stolen or
 * forged assertion must not be able to use the app's answers to work out
 * which part to fix next.
 *
 * The machine-readable {@see AssertionRefusalReason} rides alongside for
 * the AUDIT RECORD the enter endpoint writes — the server may know
 * precisely why; the caller may not.
 *
 * `$previous` carries the underlying cryptographic failure where one
 * exists, for operator debugging in server-side logs only. It never
 * reaches a response body, and it never changes this message.
 */
final class AssertionRefused extends RuntimeException
{
    /**
     * The single message every refusal carries. Deliberately says
     * nothing: two refusals for different reasons are indistinguishable
     * from the outside, string for string.
     */
    public const string MESSAGE = 'The console assertion was refused.';

    public function __construct(
        public readonly AssertionRefusalReason $reason,
        ?Throwable $previous = null,
    ) {
        parent::__construct(self::MESSAGE, 0, $previous);
    }

    public static function because(AssertionRefusalReason $reason, ?Throwable $previous = null): self
    {
        return new self($reason, $previous);
    }
}
