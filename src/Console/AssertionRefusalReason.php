<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;

/**
 * Why a console assertion was refused — a bounded, machine-readable
 * vocabulary for the AUDIT RECORD and for tests, never for the caller.
 * {@see AssertionRefused} collapses every case below into ONE exception
 * class carrying ONE uniform message, so a party feeding tokens to the
 * enter endpoint cannot tell "expired" from "wrong key" from "wrong
 * audience": the reason is reachable programmatically by the server that
 * is about to write it to the audit stream, and by nothing else.
 *
 * Every value is a bounded enum case on purpose (Console PRD D15's shape
 * discipline applied to the audit record): an audited reason is never
 * free text, so no attacker-influenced string can ride into a log line
 * or a future metadata-classified read.
 */
enum AssertionRefusalReason: string
{
    /** Not a `v4.public` token: another PASETO version, `v4.local`, or a purpose we do not speak. */
    case UnsupportedVersion = 'unsupported_version';

    /** Not a PASETO message at all — nothing parseable was presented. */
    case MalformedToken = 'malformed_token';

    /** No keyring row carries the presented `kid` (or the token names none). */
    case UnknownKey = 'unknown_key';

    /** The keyring row exists but has never been activated (or activates later). */
    case KeyNotActive = 'key_not_active';

    /** The keyring row was retired: rotation's second, separate step has happened. */
    case RetiredKey = 'retired_key';

    /** The Ed25519 signature does not verify under the named key. */
    case SignatureInvalid = 'signature_invalid';

    /** The `iss` claim is not the one configured issuer (D18). */
    case IssuerMismatch = 'issuer_mismatch';

    /** The `aud` claim names another deployment (D12's whole point). */
    case AudienceMismatch = 'audience_mismatch';

    /** `exp` has arrived. */
    case Expired = 'expired';

    /** `iat`/`nbf` sit in the future beyond the configured clock skew. */
    case NotYetValid = 'not_yet_valid';

    /** `iat`→`exp` spans longer than this deployment's own upper bound (D12). */
    case TtlTooLong = 'ttl_too_long';

    /** The `role` claim is not one of {@see ConsoleRole}. */
    case InvalidRole = 'invalid_role';

    /** A claim is absent, mistyped, over-long, or carries characters the chrome must never render. */
    case InvalidClaims = 'invalid_claims';

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
