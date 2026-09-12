<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use InvalidArgumentException;

final class OwnerCredentialMinter
{
    public function mintFromHash(string $hash): Credential
    {
        if (preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
            throw new InvalidArgumentException('A token hash must be a sha256 hex digest.');
        }

        return Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'subject_type' => SubjectType::Operator,
            'subject_ref' => 'owner',
            'name' => 'owner',
            'abilities' => [EnsureCredentialAdmin::ABILITY],
            'secret_hash' => $hash,
            'status' => CredentialStatus::Active,
        ]);
    }
}
