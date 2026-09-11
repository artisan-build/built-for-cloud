<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedTransitionStatus: string
{
    case Preparing = 'preparing';
    case Prepared = 'prepared';
    case Rostered = 'rostered';
    case Proposed = 'proposed';
    case Staging = 'staging';
    case Staged = 'staged';
    case Committed = 'committed';
    case Acknowledging = 'acknowledging';
    case Acknowledged = 'acknowledged';
    case Abandoned = 'abandoned';
}
