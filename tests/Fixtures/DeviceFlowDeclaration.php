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
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

final class DeviceFlowDeclaration implements CredentialDeclaration, DeclaresCredentialAuthorizationProfiles, DeclaresSelfServiceMintPolicy
{
    /** @var list<CredentialAuthorizationProfile> */
    public static array $profiles = [];

    public static int $authorizeCalls = 0;

    public static ?string $authorizedCredentialId = null;

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
        self::$authorizedCredentialId = (string) $credential->getKey();

        if (getenv('BFC_HARNESS_DEVICE_AUTHORIZATION') !== false
            && Schema::hasTable('bfc_device_harness_effects')) {
            DB::table('bfc_device_harness_effects')
                ->where('credential_id', self::$authorizedCredentialId)
                ->increment('authorize_calls');
        }

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
