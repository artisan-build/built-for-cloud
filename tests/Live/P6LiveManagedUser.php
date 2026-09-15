<?php

declare(strict_types=1);

namespace App\Support;

use ArtisanBuild\BuiltForCloud\User;

final class P6LiveManagedUser
{
    public static function create(): User
    {
        $staleAt = now()->subMinutes(10);
        $user = User::query()->create([
            'name' => 'P6 Managed User',
            'email' => 'p6-managed@example.test',
        ]);
        $user->forceFill([
            'role' => 'member',
            'status' => 'active',
            'scalpels_issuer' => 'https://p6-authority.test',
            'scalpels_connection_id' => 'p6-connection',
            'scalpels_id' => 'p6-managed-subject',
            'membership_confirmed_at' => $staleAt,
            'membership_checked_at' => $staleAt,
            'membership_response_at' => $staleAt,
            'managed_membership_status' => 'active',
            'managed_membership_role' => 'member',
            'managed_membership_generation' => 7,
            'managed_membership_roster_version' => 1,
            'managed_membership_response_sequence' => 1,
            'managed_membership_responded_at' => $staleAt,
        ])->save();

        return $user->refresh();
    }
}
