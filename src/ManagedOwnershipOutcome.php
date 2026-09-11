<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedOwnershipOutcome: string
{
    case OwnerAcquire = 'owner_acquire';
    case OwnershipNeutral = 'ownership_neutral';
    case OwnershipNeutralDenial = 'ownership_neutral_denial';
    case OwnershipAbsentDenial = 'ownership_absent_denial';
    case OwnerReaffirm = 'owner_reaffirm';
    case OwnerDenied = 'owner_denied';
    case OwnerContested = 'owner_contested';
}
