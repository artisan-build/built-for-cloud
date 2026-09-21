<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedAuthRefusalReason: string
{
    case OwnerSlotHeldByUnboundIdentity = 'managed_owner_slot_held_by_unbound_identity';

    /**
     * The exit commit guard: completing the transition would leave no
     * exactly-one active local Owner who can authenticate or receive
     * recovery. Distinctive so the disconnect surface (P1 A1) can
     * classify it as the bounded `owner_not_accessible` wire code.
     */
    case OwnerNotAccessible = 'owner_not_accessible';
}
