<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialAuthorizationFlow: string
{
    case Device = 'device';
    case Loopback = 'loopback';
}
