<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresUnsupportedSummaryFields;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * A reel-shaped declaration: its rows structurally carry no name, no
 * abilities, no last_used_at and no credential expiry — four of the
 * summary's fields are DECLARED unsupported, never silently null
 * (PRD 1.6, D3).
 */
final class ReelLikeDeclaration implements CredentialDeclaration, DeclaresUnsupportedSummaryFields
{
    public function unsupportedSummaryFields(): array
    {
        return ['name', 'abilities', 'last_used_at', 'expires_at'];
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
