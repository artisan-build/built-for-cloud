<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class UnparsedAppPurposeConsumer
{
    public function purpose(string $appPurpose): string
    {
        $mappings = config('built-for-cloud.credentials.app_purposes');
        $purpose = $mappings[$appPurpose];

        if (! is_string($purpose)) {
            throw new \RuntimeException('not scalar');
        }

        return $purpose;
    }
}
