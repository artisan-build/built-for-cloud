<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * Resolves the host's displayed app-purpose allow-list through the protocol
 * mapper. Protocol actions remain authoritative for kind/subject pairing.
 */
final readonly class UiCredentialPurposes
{
    public function __construct(private AppPurposeRegistry $registry) {}

    /** @return list<string> */
    public function displayed(): array
    {
        $configured = config('built-for-cloud.ui.credential_purposes');

        if (! is_array($configured) || ! array_is_list($configured)) {
            return [];
        }

        $counts = [];

        foreach ($configured as $appPurpose) {
            if (is_string($appPurpose)) {
                $counts[$appPurpose] = ($counts[$appPurpose] ?? 0) + 1;
            }
        }

        $displayed = [];

        foreach ($configured as $appPurpose) {
            if (! is_string($appPurpose) || ($counts[$appPurpose] ?? 0) !== 1) {
                continue;
            }

            try {
                $purpose = $this->registry->purpose($appPurpose);
            } catch (InvalidCredentialInput) {
                continue;
            }

            if ($purpose === CredentialPurpose::SigningRoot) {
                continue;
            }

            $displayed[] = $appPurpose;
        }

        return $displayed;
    }

    public function purposeForSubmission(string $appPurpose): CredentialPurpose
    {
        if (! in_array($appPurpose, $this->displayed(), true)) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        return $this->registry->purpose($appPurpose);
    }

    public function assertPurposeDisplayed(CredentialPurpose $purpose): void
    {
        foreach ($this->displayed() as $appPurpose) {
            if ($this->registry->purpose($appPurpose) === $purpose) {
                return;
            }
        }

        throw CredentialVerbRefused::selfServicePurpose($purpose);
    }
}
