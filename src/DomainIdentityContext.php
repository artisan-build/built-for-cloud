<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\IdentityContext;

final readonly class DomainIdentityContext implements IdentityContext
{
    private ?UserRole $resolvedRole;

    private ?AuthorityMode $resolvedAuthorityMode;

    public function __construct(
        private string $stableActorId,
        UserRole|string|null $role,
        AuthorityMode|string|null $authorityMode,
        private int $generation,
        private CredentialOwnership $ownership,
    ) {
        $this->resolvedRole = RolePolicy::role($role);
        $this->resolvedAuthorityMode = $authorityMode instanceof AuthorityMode
            ? $authorityMode
            : (is_string($authorityMode) ? AuthorityMode::tryFrom($authorityMode) : null);
    }

    public static function forUser(User $user, AuthorityState $authority): self
    {
        return new self(
            (string) $user->getKey(),
            $user->role,
            $authority->mode,
            $authority->generation,
            CredentialOwnership::Account,
        );
    }

    public function actorId(): string
    {
        return $this->stableActorId;
    }

    public function role(): ?UserRole
    {
        return $this->resolvedRole;
    }

    public function authorityMode(): ?AuthorityMode
    {
        return $this->resolvedAuthorityMode;
    }

    public function authorityGeneration(): int
    {
        return $this->generation;
    }

    public function credentialOwnership(): CredentialOwnership
    {
        return $this->ownership;
    }

    public function canUseProduct(): bool
    {
        return $this->hasValidHumanAuthority() && RolePolicy::canUseProduct($this->resolvedRole);
    }

    public function canManageMembers(): bool
    {
        return $this->hasValidHumanAuthority() && RolePolicy::canManageMembers($this->resolvedRole);
    }

    public function canManageAdmins(): bool
    {
        return $this->hasValidHumanAuthority() && RolePolicy::canManageAdmins($this->resolvedRole);
    }

    public function canInitiateModeTransition(): bool
    {
        return $this->hasValidHumanAuthority() && RolePolicy::canInitiateModeTransition($this->resolvedRole);
    }

    public function isSameActorOrAdminOrOwner(string $attributedActorId): bool
    {
        return $this->hasValidHumanAuthority()
            && RolePolicy::isSameActorOrAdminOrOwner($this->resolvedRole, $this->stableActorId, $attributedActorId);
    }

    private function hasValidHumanAuthority(): bool
    {
        return $this->ownership === CredentialOwnership::Account
            && $this->stableActorId !== ''
            && $this->resolvedAuthorityMode !== null
            && $this->generation >= 1;
    }
}
