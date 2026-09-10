<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedAccountAccess
{
    public function __construct(private ManagedFreshness $freshness) {}

    public function allows(User $user): bool
    {
        if (InstallationAuthority::current()->mode !== AuthorityMode::Managed) {
            return true;
        }

        return $this->freshness->allows($user);
    }

    public function allowsCredential(Credential $credential): bool
    {
        if ($credential->user_id === null
            || InstallationAuthority::current()->mode !== AuthorityMode::Managed) {
            return true;
        }

        $user = User::query()->find($credential->user_id);

        return $user instanceof User && $this->freshness->allows($user);
    }
}
