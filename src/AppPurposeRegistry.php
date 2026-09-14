<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * Maps an app-owned operation id to exactly one package protocol purpose.
 * Display configuration is deliberately outside this enforcement boundary.
 */
final class AppPurposeRegistry
{
    public function purpose(string $appPurpose): CredentialPurpose
    {
        if (preg_match('/^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$/D', $appPurpose) !== 1) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        $mappings = config('built-for-cloud.credentials.app_purposes');

        if (! is_array($mappings) || ! array_key_exists($appPurpose, $mappings)) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        $purpose = $mappings[$appPurpose];

        if (! is_string($purpose)) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        return CredentialPurpose::tryFrom($purpose)
            ?? throw InvalidCredentialInput::invalidAppPurposeMapping();
    }
}
