<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class HumanInvitationResult
{
    public function __construct(
        public Invitation $invitation,
        public MintedSecret $token,
    ) {}
}
