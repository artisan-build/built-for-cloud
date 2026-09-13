<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedAuthRefusalReason: string
{
    case OwnerSlotHeldByUnboundIdentity = 'managed_owner_slot_held_by_unbound_identity';
}
