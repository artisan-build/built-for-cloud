<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum ManagedEnrolmentRequestKind: string
{
    case Enrolment = 'enrolment';

    case ClientSecretRotation = 'client_secret_rotation';

    case Disconnect = 'disconnect';
}
