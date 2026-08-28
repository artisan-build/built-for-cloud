<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * How a mint's secret reaches its holder (PRD 1.6, FLT-R5). The shape is
 * part of {@see MintResult} because a summary alone cannot express what v1's
 * own requirements demanded the issuance surface emit: a bearer value, an
 * `auth.json` fragment, or an enrollment code are three different deliveries,
 * and "none" is a real answer, not a missing one.
 */
enum DeliveryShape: string
{
    /** A token string, presented as `Authorization: Bearer <token>`. */
    case Bearer = 'bearer';

    /**
     * A username/password pair for Composer's `auth.json` (HTTP Basic).
     * The username is presentation-only and grants nothing; the password
     * is the secret.
     */
    case BasicAuth = 'basic_auth';

    /**
     * A short-lived claim code the client redeems by generating its own
     * keypair. The code is minted through the claim primitive; it NEVER
     * carries key material — the private key never exists server-side.
     */
    case EnrollmentCode = 'enrollment_code';

    /**
     * A per-subject hmac signing key, revealed ONCE in this result — the
     * operator-controlled-counterparty path (D7, e.g. capstan hub↔spoke).
     * The key is PENDING: it signs nothing and verifies nothing until the
     * separate activation verb cuts it over (SEC-V3-01).
     */
    case SigningKey = 'signing_key';

    /**
     * A claim-primitive code whose EXCHANGE delivers a pending hmac
     * signing key to an outside counterparty. The exchange delivers the
     * key material and NEVER activates (SEC-V3-01): an inbox interceptor
     * who redeems the link learns a key that signs nothing and verifies
     * nothing, and live signing state is untouched.
     */
    case SigningKeyCode = 'signing_key_code';

    /** The secret was never ours to hand over. */
    case None = 'none';
}
