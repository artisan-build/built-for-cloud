<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\IdentityContext;

final readonly class ReelProtectionDecision
{
    public function __construct(private IdentityContext $identity) {}

    public function canUnprotect(string $protectorId): bool
    {
        return $this->identity->isSameActorOrAdminOrOwner($protectorId);
    }
}
