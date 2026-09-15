<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Throwable;

/** Exact-scope, model-free verification-key selection. */
final class AsymmetricVerificationKeys
{
    public function __construct(private readonly AppPurposeRegistry $appPurposes) {}

    /** @return list<AsymmetricVerificationKey> */
    public function for(BoundCredentialScope $scope): array
    {
        $purpose = $this->appPurposes->purpose($scope->appPurpose);

        if ($purpose !== CredentialPurpose::Signing) {
            return [];
        }

        $algorithm = CredentialAlgorithm::Rs256;
        $role = CredentialMaterialRole::Originator;
        $hash = CredentialProtocolBinding::scopeHash($scope, $purpose, $algorithm, $role);

        $rows = DB::table('credential_protocol_bindings as bindings')
            ->join('credentials', 'credentials.id', '=', 'bindings.credential_id')
            ->where('bindings.scope_hash', $hash)
            ->where('bindings.app_purpose', $scope->appPurpose)
            ->where('bindings.installation_ref', $scope->installation)
            ->where('bindings.application_ref', $scope->application)
            ->where('bindings.audience', $scope->audience)
            ->where('bindings.algorithm', $algorithm->value)
            ->where('bindings.material_role', $role->value)
            ->where('credentials.kind', CredentialKind::Asymmetric->value)
            ->where('credentials.purpose', $purpose->value)
            ->where('credentials.subject_type', $scope->subject->type->value)
            ->where('credentials.subject_ref', $scope->subject->ref)
            ->where('credentials.status', CredentialStatus::Active->value)
            ->whereNull('credentials.user_id')
            ->whereNull('credentials.revoked_at')
            ->where(function (Builder $query): void {
                $query->whereNull('credentials.expires_at')->orWhere('credentials.expires_at', '>', now());
            })
            ->whereNotNull('credentials.public_key')
            ->orderByDesc('credentials.activated_at')
            ->orderByDesc('credentials.created_at')
            ->orderByDesc('credentials.id')
            ->get(['credentials.id', 'credentials.public_key']);

        $keys = [];

        foreach ($rows as $row) {
            if (! is_string($row->id) || ! is_string($row->public_key)) {
                continue;
            }

            try {
                $publicKey = new Rs256PublicKey($row->public_key);
            } catch (Throwable) {
                continue;
            }

            if (! hash_equals($publicKey->pem, $row->public_key)) {
                continue;
            }

            $keys[] = new AsymmetricVerificationKey($row->id, $publicKey->pem, $algorithm);
        }

        return $keys;
    }
}
