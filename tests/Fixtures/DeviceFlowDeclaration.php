<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresCredentialAuthorizationProfiles;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

final class DeviceFlowDeclaration implements CredentialDeclaration, DeclaresCredentialAuthorizationProfiles, DeclaresSelfServiceMintPolicy
{
    /** @var list<CredentialAuthorizationProfile> */
    public static array $profiles = [];

    public static int $authorizeCalls = 0;

    public static ?Subject $resolvedSubject = null;

    /** @var list<string> */
    public static array $selfServiceAbilities = [];

    /** @var list<CredentialKind> */
    public static array $selfServiceKinds = [CredentialKind::Bearer];

    public function resolveSubject(Request $request): ?Subject
    {
        return self::$resolvedSubject;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        self::$authorizeCalls++;

        return true;
    }

    public function credentialAuthorizationProfiles(Request $request): array
    {
        return self::$profiles;
    }

    public function selfServiceAbilities(Subject $subject): array
    {
        return self::$selfServiceAbilities;
    }

    public function selfServiceKinds(Subject $subject): array
    {
        return self::$selfServiceKinds;
    }
}
