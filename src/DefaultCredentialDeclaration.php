<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use Illuminate\Http\Request;

/**
 * The declaration the package ships so it works out of the box: no subject
 * derivation, and authorization defers entirely to the credential's own
 * lifecycle and abilities (which the guard and middleware already enforce).
 */
final class DefaultCredentialDeclaration implements CredentialDeclaration
{
    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }
}
