<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;

/**
 * Why `POST /bfc/console/enter` refused an entry for a reason the
 * ASSERTION ITSELF was not refused for (Console PRD D12/D13) — a
 * bounded, machine-readable vocabulary for the AUDIT RECORD, never for
 * the caller.
 *
 * It is the sibling of {@see AssertionRefusalReason} and the two are
 * deliberately DISJOINT value sets: the verifier owns everything about
 * the token (signature, issuer, audience, clocks, claim shapes), and
 * this enum owns everything the endpoint decides after the token has
 * verified — purpose, the single-use burn, the signed handoff state, and
 * the return path. One audit note therefore carries exactly one value from
 * exactly one of the two vocabularies, and a reader never has to
 * disambiguate.
 *
 * Every value is a bounded enum case for the same reason D15 bounds a
 * metadata field: an audited reason is never free text, so no
 * attacker-influenced string can ride into a log line.
 *
 * {@see ConsoleEntryRefused} collapses every case below — and every
 * {@see AssertionRefusalReason} — into ONE response, so a presenter
 * cannot tell a replay from a wrong audience from a bad signature.
 */
enum ConsoleEntryRefusalReason: string
{
    /** No `assertion` field, or one that is not a non-empty string. */
    case MissingAssertion = 'missing_assertion';

    /** No `state` field, or one that is not a non-empty string within the bound. */
    case StateMissing = 'state_missing';

    /**
     * The mint carried no `state` claim, so nothing signed binds a
     * return path to it — an UNSIGNED state, which is refused rather
     * than treated as "no return path" (D13).
     */
    case StateUnsigned = 'state_unsigned';

    /**
     * The presented `state` does not hash to the digest the assertion
     * signed: it was tampered with, substituted, or belongs to another
     * mint.
     */
    case StateMismatch = 'state_mismatch';

    /** The state decodes to nothing this endpoint can read as a handoff state. */
    case StateMalformed = 'state_malformed';

    /**
     * The state's `return_to` is not a safe same-origin relative path
     * in every percent-decoded form ({@see ConsoleReturnTo}), or the
     * deployment's configured allowlist does not cover it.
     */
    case ReturnPathRefused = 'return_path_refused';

    /** The assertion was verified, but was minted for the other door. */
    case PurposeMismatch = 'purpose_mismatch';

    /**
     * The mint identifier (`jti`) is already spent. This is the
     * single-use burn (D12) reporting a genuine second presentation.
     */
    case Replayed = 'replayed';

    /**
     * This deployment has contained the actor the assertion names. The
     * issuer still vouches for the human; this deployment does not.
     */
    case ActorDeactivated = 'actor_deactivated';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $reason): string => $reason->value,
            self::cases(),
        );
    }
}
