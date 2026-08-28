<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The bounded `reason_code` on an audit event (D8 adjustment 3): revocation
 * reasons are an enum plus a bounded free-text note, never unbounded prose
 * alone. `Offboarding` and `Expired` are in the vocabulary for the
 * offboarding verb and expiry sweeps of later PRs.
 */
enum AuditReason: string
{
    case OperatorRequest = 'operator_request';
    case HolderRequest = 'holder_request';
    case Offboarding = 'offboarding';
    case Rotation = 'rotation';

    /**
     * A rotation that changed abilities or lifetime under the explicit
     * override flag (PRD 1.7): its own reason code, with the delta in the
     * event's note, so a routine rotation and a privilege change are never
     * the same audit row.
     */
    case Override = 'override';
    case Superseded = 'superseded';
    case Emergency = 'emergency';
    case Expired = 'expired';
}
