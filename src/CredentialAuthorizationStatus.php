<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialAuthorizationStatus: string
{
    case Pending = 'pending';
    case Approved = 'approved';
    case Denied = 'denied';
    case Consumed = 'consumed';
}
