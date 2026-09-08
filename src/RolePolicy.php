<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final class RolePolicy
{
    public static function role(UserRole|string|null $role): ?UserRole
    {
        return $role instanceof UserRole ? $role : (is_string($role) ? UserRole::tryFrom($role) : null);
    }

    public static function canUseProduct(UserRole|string|null $role): bool
    {
        return self::role($role) !== null;
    }

    public static function canManageMembers(UserRole|string|null $role): bool
    {
        return in_array(self::role($role), [UserRole::Owner, UserRole::Admin], true);
    }

    public static function canManageAdmins(UserRole|string|null $role): bool
    {
        return self::role($role) === UserRole::Owner;
    }

    public static function canManage(UserRole|string|null $role, UserRole|string|null $target): bool
    {
        return match (self::role($target)) {
            UserRole::Member => self::canManageMembers($role),
            UserRole::Admin => self::canManageAdmins($role),
            default => false,
        };
    }

    public static function canInitiateModeTransition(UserRole|string|null $role): bool
    {
        return self::role($role) === UserRole::Owner;
    }

    public static function isSameActorOrAdminOrOwner(
        UserRole|string|null $role,
        string $actorId,
        string $attributedActorId,
    ): bool {
        $resolved = self::role($role);

        if ($resolved === null) {
            return false;
        }

        return hash_equals($actorId, $attributedActorId)
            || in_array($resolved, [UserRole::Owner, UserRole::Admin], true);
    }
}
