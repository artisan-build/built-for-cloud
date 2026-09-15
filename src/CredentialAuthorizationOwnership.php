<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialAuthorizationOwnership: string
{
    case Personal = 'personal';
    case Installation = 'installation';
}
