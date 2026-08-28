<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The instance-REPORTED status of a listed credential row (PRD 1.5).
 *
 * This package reports; it does not judge. The value is an INPUT to the
 * consuming control plane's own status mapper — Scalpels' mapper stays
 * authoritative for connection health (FLT-H) and composes this with what
 * it knows that the instance does not. Two rules the consumer must honour:
 *
 * - `Unknown` NEVER escalates to a failure state (FLT-R2). It means the
 *   row structurally cannot carry a usage signal — a signal that cannot
 *   move is not a signal that stopped.
 * - `Revoked` is asked before expiry: a row that is both revoked and
 *   expired reports `revoked`, because revocation is the deliberate act.
 *
 * On the `api_tokens` store every row structurally carries the usage
 * signal (`last_used_at` / `request_count` exist on every row), so this
 * provider never emits `Unknown` — the case is RESERVED in the vocabulary
 * for stores whose rows cannot carry it (an asymmetric build-time
 * credential, for one), not invented here.
 */
enum ReportedStatus: string
{
    case Active = 'active';
    case Expired = 'expired';
    case Revoked = 'revoked';
    case Unknown = 'unknown';
}
