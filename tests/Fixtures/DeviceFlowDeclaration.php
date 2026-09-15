<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresCredentialAuthorizationProfiles;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

final class DeviceFlowDeclaration implements CredentialDeclaration, DeclaresCredentialAuthorizationProfiles, DeclaresSelfServiceMintPolicy
{
    /** @var list<CredentialAuthorizationProfile> */
    public static array $profiles = [];

    public static int $authorizeCalls = 0;

    /** @var list<string> */
    public static array $selfServiceAbilities = [];

    public function resolveSubject(Request $request): ?Subject
    {
        foreach (self::$profiles as $profile) {
            if ($profile->ownership === CredentialAuthorizationOwnership::Personal) {
                return $profile->scope->subject;
            }
        }

        return null;
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
        return [CredentialKind::Bearer];
    }
}
