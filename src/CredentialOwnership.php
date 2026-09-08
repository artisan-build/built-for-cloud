<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialOwnership: string
{
    case Account = 'account';
    case Installation = 'installation';
}
