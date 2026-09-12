<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * The seam's unified-store implementation (PRD 1.0): exchange mints a
 * `credentials` row instead of an `api_tokens` row when the app's
 * declaration targets {@see DurableStore::Credentials}. The claim
 * primitive itself is untouched — that is the whole point of the seam.
 *
 * The subject is `external_consumer` with the claim's name as its ref:
 * exchange-minted durables belong to the outside party the code was
 * addressed to, and the name doubles as the ref until the consuming app's
 * declaration takes over subject derivation at rebuild time.
 */
final class UnifiedStoreCredentialMinter implements DurableCredentialMinter
{
    public function mint(string $name, string $scope): MintedDurableCredential
    {
        $scope = Scope::tryFrom($scope);

        if ($scope === null) {
            throw InvalidCredentialInput::unknownScope();
        }

        [$purpose, $subjectType, $abilities] = match ($scope) {
            Scope::Consume => [CredentialPurpose::Consumption, SubjectType::ExternalConsumer, []],
            Scope::Admin => [CredentialPurpose::OperatorManagement, SubjectType::Operator, [OperatorAbility::Admin->value]],
            Scope::Onboard => [CredentialPurpose::Enrollment, SubjectType::ExternalConsumer, []],
        };

        $secret = new MintedSecret(
            (string) config('built-for-cloud.token_prefix').bin2hex(random_bytes(32)),
        );

        $credential = Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'purpose' => $purpose,
            'subject_type' => $subjectType,
            'subject_ref' => $name,
            'name' => $name,
            'abilities' => $abilities,
            'secret_hash' => $secret->hash(),
            'status' => CredentialStatus::Active,
        ]);

        return new MintedDurableCredential($secret, $credential);
    }
}
