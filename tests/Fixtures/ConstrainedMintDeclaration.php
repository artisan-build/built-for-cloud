<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * A declaration with mint ceilings: only `consume` is grantable and no
 * credential may live longer than an hour. The widening-refusal fixture
 * (locked AC 2).
 */
final class ConstrainedMintDeclaration implements ConstrainsMintedCredentials, CredentialDeclaration
{
    public function grantableAbilities(Subject $subject): ?array
    {
        return ['consume'];
    }

    public function maxCredentialLifetimeSeconds(Subject $subject): ?int
    {
        return 3600;
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
