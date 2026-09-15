<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use Illuminate\Http\Request;

/** Optional policy surface for browser-approved bearer issuance. */
interface DeclaresCredentialAuthorizationProfiles
{
    /** @return list<CredentialAuthorizationProfile> */
    public function credentialAuthorizationProfiles(Request $request): array;
}
