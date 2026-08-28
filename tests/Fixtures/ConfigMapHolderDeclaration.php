<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\BurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHolderResolution;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * A declaration that resolves holders from a config map — the test stand-in
 * for an app whose credentials bind to users: credential id => that bound
 * user's email. Anything not in the map is an unbound subject and resolves
 * to NOBODY.
 */
final class ConfigMapHolderDeclaration implements CredentialDeclaration, DeclaresBurnMode, DeclaresHolderResolution
{
    public function burnMode(): BurnMode
    {
        return BurnMode::FirstUse;
    }

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    public function resolveHolderEmail(string $credentialId): ?string
    {
        $map = config('built-for-cloud-tests.holder_map', []);

        return is_array($map) && is_string($map[$credentialId] ?? null) ? $map[$credentialId] : null;
    }
}
