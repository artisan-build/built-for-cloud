<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * The explicit lifecycle states a credential can hold. Revocation and expiry
 * are carried by `revoked_at` / `expires_at` rather than status values, so a
 * row keeps its history when it dies.
 */
enum CredentialStatus: string
{
    case Pending = 'pending';
    case Active = 'active';
}
