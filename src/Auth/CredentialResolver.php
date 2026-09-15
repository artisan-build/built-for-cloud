<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use Carbon\CarbonInterface;

/**
 * Hash lookup against the unified store. A presented secret resolves only a
 * row of the presenting kind that is active, unrevoked, unexpired and not
 * pending. Only persisted credentials participate; there is no environment
 * pseudo-credential path.
 *
 * THE CONTAINMENT CHOKE POINT (PRD 1.15, SEC-V3-04, rework 3 Fix 1): the
 * offboarded-registry rejection lives HERE, in the one method every
 * unified-store secret resolution flows through — the `bfc` guard's
 * authenticators, `CredentialGuard::validate()`, the operator gate, the
 * onboarding verify surface, and any future caller alike. A credential
 * whose subject — or bound user — is offboarded resolves to NULL
 * everywhere, structurally: a new resolution path cannot forget the check,
 * because it cannot resolve without it. The non-resolution rejection —
 * indistinguishable from an unknown secret — also means no caller ever
 * records a use, first-use-burns a code, or leaks that the principal
 * exists.
 *
 * The ONE credential-authentication path that does not pass through this
 * resolver is {@see HmacVerifier}'s key selection (keys are selected by
 * server-derived subject + key id, never by secret hash); it carries its
 * own registry check for exactly that reason — load-bearing there, not
 * defense-in-depth.
 */
final class CredentialResolver
{
    public function __construct(private readonly ManagedAccountAccess $managedAccess) {}

    public function resolve(CredentialKind $kind, ?string $secret): ?Credential
    {
        if ($secret === null || $secret === '') {
            return null;
        }

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->where('kind', $kind->value)
            ->where('secret_hash', hash('sha256', $secret))
            ->whereNotExists(function ($query): void {
                $query->selectRaw('1')
                    ->from('credential_protocol_bindings')
                    ->whereColumn('credential_protocol_bindings.credential_id', 'credentials.id');
            })
            ->active()
            ->first();

        if ($credential === null
            || OffboardedSubject::rejects($credential)
            || ! $this->managedAccess->allowsCredential($credential)) {
            return null;
        }

        return $credential;
    }

    /** @param list<string> $abilities */
    public function resolveBoundBearer(
        BoundCredentialScope $scope,
        CredentialAuthorizationOwnership $ownership,
        array $abilities,
        ?CarbonInterface $expiresAt,
        ?string $secret,
    ): ?Credential {
        if ($secret === null || $secret === '') {
            return null;
        }

        $purpose = app(AppPurposeRegistry::class)->purpose($scope->appPurpose);
        $algorithm = CredentialAlgorithm::Bearer;
        $role = CredentialMaterialRole::Originator;
        $scopeHash = CredentialProtocolBinding::scopeHash($scope, $purpose, $algorithm, $role);

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->select('credentials.*')
            ->join('credential_protocol_bindings as binding', 'binding.credential_id', '=', 'credentials.id')
            ->where('credentials.kind', CredentialKind::Bearer->value)
            ->where('credentials.secret_hash', hash('sha256', $secret))
            ->where('credentials.purpose', $purpose->value)
            ->where('credentials.subject_type', $scope->subject->type->value)
            ->where('credentials.subject_ref', $scope->subject->ref)
            ->where('binding.app_purpose', $scope->appPurpose)
            ->where('binding.installation_ref', $scope->installation)
            ->where('binding.application_ref', $scope->application)
            ->where('binding.audience', $scope->audience)
            ->where('binding.algorithm', $algorithm->value)
            ->where('binding.material_role', $role->value)
            ->where('binding.scope_hash', $scopeHash)
            ->when(
                $ownership === CredentialAuthorizationOwnership::Installation,
                static fn ($query) => $query->whereNull('credentials.user_id'),
                static fn ($query) => $query->whereNotNull('credentials.user_id'),
            )
            ->active()
            ->first();

        if ($credential === null) {
            return null;
        }

        /** @var CredentialProtocolBinding|null $binding */
        $binding = CredentialProtocolBinding::query()->whereKey($credential->id)->first();

        if ($binding === null
            || ! $binding->exactlyMatches($credential, $scope, $purpose, $algorithm, $role)
            || ($credential->abilities ?? []) !== $abilities
            || $credential->expires_at?->getTimestamp() !== $expiresAt?->getTimestamp()
            || OffboardedSubject::rejects($credential)
            || ! $this->managedAccess->allowsCredential($credential)) {
            return null;
        }

        return $credential;
    }
}
