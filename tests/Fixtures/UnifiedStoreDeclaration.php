<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * A permissive declaration used by unified credential tests. Burn mode is
 * not declared, so the default `first_use` applies.
 */
final class UnifiedStoreDeclaration implements CredentialDeclaration
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
