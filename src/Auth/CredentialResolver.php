<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;

/**
 * Hash lookup against the unified store. A presented secret resolves only a
 * row of the presenting kind that is active, unrevoked, unexpired and not
 * pending. There is deliberately NO fallback-token path here: the env
 * pseudo-credential is a legacy `TokenRegistry` concern the new guard never
 * consults.
 */
final class CredentialResolver
{
    public function resolve(CredentialKind $kind, ?string $secret): ?Credential
    {
        if ($secret === null || $secret === '') {
            return null;
        }

        /** @var Credential|null */
        return Credential::query()
            ->where('kind', $kind->value)
            ->where('secret_hash', hash('sha256', $secret))
            ->active()
            ->first();
    }
}
