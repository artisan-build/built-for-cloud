<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\CredentialOwnership;
use ArtisanBuild\BuiltForCloud\UserRole;

interface IdentityContext
{
    public function actorId(): string;

    public function role(): ?UserRole;

    public function authorityMode(): ?AuthorityMode;

    public function authorityGeneration(): int;

    public function credentialOwnership(): CredentialOwnership;

    public function canUseProduct(): bool;

    public function canManageMembers(): bool;

    public function canManageAdmins(): bool;

    public function canInitiateModeTransition(): bool;

    public function isSameActorOrAdminOrOwner(string $attributedActorId): bool;
}
