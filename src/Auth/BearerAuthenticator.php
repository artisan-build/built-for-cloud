<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use Illuminate\Http\Request;

/**
 * `Authorization: Bearer <secret>` against `bearer` rows.
 */
final class BearerAuthenticator implements CredentialAuthenticator
{
    public function __construct(private readonly CredentialResolver $resolver) {}

    public function credential(Request $request): ?Credential
    {
        return $this->resolver->resolve(CredentialKind::Bearer, $request->bearerToken());
    }
}
