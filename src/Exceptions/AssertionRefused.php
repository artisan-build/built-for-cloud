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
 * {@see self::MESSAGE}. The CLASS and the MESSAGE are identical for all
 * thirteen reasons, so nothing an attacker reads back — from the
 * exception, or from the uniform response the enter endpoint renders
 * from it — says whether the signature was wrong, the key unknown, the
 * audience another deployment's, or the clock past `exp`.
 *
 * That is a bound on what the ANSWER carries, not on every channel: a
 * refusal decided before the Ed25519 verification (an unknown, pending
 * or retired `kid`) returns measurably sooner than one decided after it,
 * so key state remains distinguishable by TIMING. That is a deliberate
 * non-goal — the assertion's own audience binding and single-use burn
 * are what make a stolen or forged token worthless, and constant-time
 * padding here would cost real latency on a page-load path to hide
 * which key id a prober already chose. What the message must never do
 * is hand the answer over for free, and it does not.
 *
 * {@see AssertionVerifier} throws this and nothing else, so the enter
 * endpoint has exactly one refusal shape to render. The machine-readable
 * {@see AssertionRefusalReason} rides alongside for the AUDIT RECORD
 * that endpoint writes — the server may know precisely why; the caller
 * may not.
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
