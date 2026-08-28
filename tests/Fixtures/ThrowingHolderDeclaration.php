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
use RuntimeException;

/**
 * A notification subscriber that fails: holder resolution throws, the way a
 * broken app hook or dead mail dependency would mid-delivery.
 */
final class ThrowingHolderDeclaration implements CredentialDeclaration, DeclaresBurnMode, DeclaresHolderResolution
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
        throw new RuntimeException('simulated subscriber failure');
    }
}
