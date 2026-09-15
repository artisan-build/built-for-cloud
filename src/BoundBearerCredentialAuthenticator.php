<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use Illuminate\Http\Request;

final class BoundBearerCredentialAuthenticator
{
    private ?Request $resolvedFor = null;

    private ?string $resolvedKey = null;

    private bool $attempted = false;

    private ?BoundBearerCredential $resolved = null;

    public function __construct(
        private readonly CredentialAuthorizationPolicy $policy,
        private readonly CredentialResolver $resolver,
        private readonly CredentialDeclaration $declaration,
        private readonly CredentialUsageRecorder $usage,
        private readonly ClientIdentityRecorder $clientIdentities,
    ) {}

    public function authenticate(Request $request, string $appPurpose, ?string $ability = null): ?BoundBearerCredential
    {
        [$profile, $purpose] = $this->policy->forUse($request, $appPurpose);
        $key = CredentialProtocolBinding::scopeHash(
            $profile->scope,
            $purpose,
            CredentialAlgorithm::Bearer,
            CredentialMaterialRole::Originator,
        )."\0".hash('sha256', (string) $request->bearerToken())."\0".(string) $ability;

        if ($this->resolvedFor !== $request || $this->resolvedKey !== $key) {
            $this->resolvedFor = $request;
            $this->resolvedKey = $key;
            $this->attempted = false;
            $this->resolved = null;
        }

        if ($this->attempted) {
            return $this->resolved;
        }

        $this->attempted = true;
        $credential = $this->resolver->resolveBoundBearer(
            $profile->scope,
            $profile->ownership,
            $this->policy->canonicalAbilities($profile->abilities),
            $profile->expiresAt,
            $request->bearerToken(),
        );

        if ($credential === null
            || ($ability !== null && ! $credential->hasAbility($ability))
            || ! $this->declaration->authorize($credential, $ability, $request)
            || ! $this->usage->recordUsage($credential)) {
            return null;
        }

        $this->clientIdentities->recordClientIdentityFromRequest($request, $credential);

        return $this->resolved = new BoundBearerCredential(
            $credential->id,
            $profile->scope,
            $credential->user_id === null
                ? CredentialAuthorizationOwnership::Installation
                : CredentialAuthorizationOwnership::Personal,
            $credential->abilities ?? [],
            $credential->user_id,
            $credential->expires_at,
        );
    }
}
