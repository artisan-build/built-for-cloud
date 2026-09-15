<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialMaterialRole: string
{
    case Originator = 'originator';
    case VerificationCopy = 'verification_copy';
}
