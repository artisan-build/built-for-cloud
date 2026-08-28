<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHolderResolution;
use Illuminate\Http\Request;

/**
 * The declaration the package ships so it works out of the box: no subject
 * derivation, authorization defers entirely to the credential's own
 * lifecycle and abilities (which the guard and middleware already enforce),
 * claim codes burn on first use — the `api_tokens` provider's mode — and
 * holder notifications resolve to NOBODY.
 */
final class DefaultCredentialDeclaration implements CredentialDeclaration, DeclaresBurnMode, DeclaresHolderResolution
{
    public function burnMode(): BurnMode
    {
        return BurnMode::FirstUse;
    }

    /**
     * NOBODY, deliberately: the default store binds credentials to no
     * person, and an unbound subject notifies no one — there is no
     * operator fallback to spam (PRD 1.16).
     */
    public function resolveHolderEmail(string $credentialId): ?string
    {
        return null;
    }

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }
}
