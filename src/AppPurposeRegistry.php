<?php

declare(strict_types=1);
namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

final class AppPurposeRegistry
{
    public function protocolPurpose(string $appPurpose): CredentialPurpose
    {
        $mapping = config('built-for-cloud.credentials.app_purposes', []);
        $mapped = is_array($mapping) ? ($mapping[$appPurpose] ?? null) : null;

        if (preg_match('/^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$/', $appPurpose) !== 1
            || ! is_string($mapped)
            || CredentialPurpose::tryFrom($mapped) === null) {
            throw InvalidCredentialInput::unknownAppPurpose($appPurpose);
        }

        return CredentialPurpose::from($mapped);
    }
}
