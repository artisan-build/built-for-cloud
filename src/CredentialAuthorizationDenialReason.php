<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum CredentialAuthorizationDenialReason: string
{
    case UserDenied = 'user_denied';
    case ProfileWithdrawn = 'profile_withdrawn';
    case AuthorityDenied = 'authority_denied';
    case UserRemoved = 'user_removed';
    case SubjectOffboarded = 'subject_offboarded';
    case InstallationRemoved = 'installation_removed';
    case ConnectionInactive = 'connection_inactive';
}
