<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\CredentialPurpose;

final class UiConditionedPurposeGate
{
    public function allows(CredentialPurpose $purpose): bool
    {
        return config('built-for-cloud.ui.personal_credentials') === true
            && $purpose === CredentialPurpose::Consumption;
    }
}
