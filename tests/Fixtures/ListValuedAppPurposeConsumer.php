<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\CredentialPurpose;

final class ListValuedAppPurposeConsumer
{
    /** @return list<CredentialPurpose> */
    public function purposes(string $appPurpose): array
    {
        $mappings = config('built-for-cloud.credentials.app_purposes');
        $purposes = $mappings[$appPurpose];

        if (! is_array($purposes)) {
            return [];
        }

        return array_map(CredentialPurpose::from(...), $purposes);
    }
}
