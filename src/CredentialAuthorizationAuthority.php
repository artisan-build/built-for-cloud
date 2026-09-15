<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialAuthorizationAuthority
{
    case Allowed;
    case Denied;
    case Unavailable;
}
