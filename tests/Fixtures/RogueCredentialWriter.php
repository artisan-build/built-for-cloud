<?php

declare(strict_types=1);

namespace Fixtures;

use ArtisanBuild\BuiltForCloud\Credential;

final class RogueCredentialWriter
{
    public function write(): Credential
    {
        return Credential::query()->create([
            'kind' => 'bearer',
            'subject_type' => 'application',
            'subject_ref' => 'rogue',
        ]);
    }
}
