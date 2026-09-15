<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresCredentialAuthorizationProfiles;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class CredentialAuthorizationPolicy
{
    public function __construct(
        private CredentialDeclaration $declaration,
        private AppPurposeRegistry $appPurposes,
        private SelfServiceKindPolicyResolver $kindPolicy,
        private ManagedAccountAccess $managedAccess,
        private ActingPrincipalResolver $principals,
    ) {}

    /** @return array{CredentialAuthorizationProfile, CredentialPurpose, string} */
    public function start(Request $request, string $appPurpose): array
    {
        $acting = $this->principals->resolve();
        $userId = $acting->identifier();

        if ($acting->wasRefused() || $acting->delegatedSessionPresent() || ! $acting->principal instanceof Authenticatable || $userId === null) {
            throw CredentialAuthorizationRefused::denied();
        }

        $profile = $this->profile($request, $appPurpose);
        $purpose = $this->validate($request, $profile, (string) $userId, true);

        return [$profile, $purpose, (string) $userId];
    }

    /** @return array{CredentialAuthorizationProfile, CredentialPurpose} */
    public function forUse(Request $request, string $appPurpose): array
    {
        $profile = $this->profile($request, $appPurpose);
        $purpose = $this->appPurposes->purpose($profile->appPurpose);

        if (! hash_equals($profile->appPurpose, $profile->scope->appPurpose)
            || ! $purpose->allowedFor(CredentialKind::Bearer, $profile->scope->subject->type)) {
            throw InvalidCredentialInput::boundScopeMismatch();
        }

        $abilities = $this->canonicalAbilities($profile->abilities);

        if ($profile->ownership === CredentialAuthorizationOwnership::Installation
            && (! in_array($profile->scope->subject->type, [SubjectType::Application, SubjectType::Installation], true)
                || array_intersect($abilities, OperatorAbility::vocabulary()) !== [])) {
            throw InvalidCredentialInput::boundScopeMismatch();
        }

        return [$profile, $purpose];
    }

    /** @return array{CredentialAuthorizationProfile, CredentialPurpose} */
    public function revalidate(Request $request, object $authorization): array
    {
        try {
            $profile = $this->profile($request, (string) $authorization->app_purpose);
            $purpose = $this->validate($request, $profile, (string) $authorization->initiating_user_id, false);
        } catch (InvalidCredentialInput|CredentialAuthorizationRefused|CredentialVerbRefused) {
            throw CredentialAuthorizationRefused::denied();
        }

        $abilities = $this->canonicalAbilities($profile->abilities);
        $storedAbilities = json_decode((string) $authorization->abilities, true);

        if (! is_array($storedAbilities)
            || $purpose->value !== $authorization->protocol_purpose
            || $profile->ownership->value !== $authorization->ownership
            || $profile->scope->subject->type->value !== $authorization->subject_type
            || ! $this->same($profile->scope->subject->ref, $authorization->subject_ref)
            || ! $this->same($profile->scope->installation, $authorization->installation_ref)
            || ! $this->same($profile->scope->application, $authorization->application_ref)
            || ! $this->same($profile->scope->audience, $authorization->audience)
            || $abilities !== $storedAbilities
            || $this->timestamp($profile->expiresAt) !== $this->timestamp($authorization->credential_expires_at)
            || $profile->codeTtlSeconds !== $authorization->profile_code_ttl_seconds
            || $profile->initialPollInterval !== $authorization->profile_initial_poll_interval) {
            throw CredentialAuthorizationRefused::denied();
        }

        return [$profile, $purpose];
    }

    public function requestForAuthorization(Request $request, object $authorization): Request
    {
        $current = $request->user();

        if ($current instanceof Authenticatable
            && (string) $current->getAuthIdentifier() === (string) $authorization->initiating_user_id) {
            return $request;
        }

        $model = config('auth.providers.users.model', User::class);
        $user = is_string($model) && is_subclass_of($model, Model::class)
            ? $model::query()->find((string) $authorization->initiating_user_id)
            : null;
        $context = clone $request;
        $context->setUserResolver(static fn (): mixed => $user instanceof Authenticatable ? $user : null);

        return $context;
    }

    public function authority(
        CredentialAuthorizationProfile $profile,
        Request $request,
        string $initiatingUserId,
        bool $installationExchange = false,
    ): CredentialAuthorizationAuthority {
        if (InstallationAuthority::current()->mode !== AuthorityMode::Managed) {
            return CredentialAuthorizationAuthority::Allowed;
        }

        $connectionStatus = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->value('managed_connection_status');

        if ($connectionStatus === 'inactive') {
            return CredentialAuthorizationAuthority::Denied;
        }

        $principal = $request->user();
        $user = $principal instanceof User && (string) $principal->getAuthIdentifier() === $initiatingUserId
            ? $principal
            : User::query()->find($initiatingUserId);

        if (! $user instanceof User && $installationExchange) {
            $connection = ManagedAuthConnection::current();
            $user = User::query()
                ->where('scalpels_issuer', $connection->issuer)
                ->where('scalpels_connection_id', $connection->connectionId)
                ->whereNotNull('scalpels_id')
                ->first();
        }

        if (! $user instanceof User) {
            return $installationExchange
                ? CredentialAuthorizationAuthority::Unavailable
                : CredentialAuthorizationAuthority::Denied;
        }

        $allowed = $this->managedAccess->allows($user);
        $user->refresh();
        $connectionStatus = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->value('managed_connection_status');

        if ($connectionStatus === 'inactive') {
            return CredentialAuthorizationAuthority::Denied;
        }

        if ($profile->ownership === CredentialAuthorizationOwnership::Installation && $installationExchange) {
            if ($allowed) {
                return CredentialAuthorizationAuthority::Allowed;
            }

            $responseAt = $this->timestamp($user->membership_response_at);
            $age = $responseAt === null ? PHP_INT_MAX : now()->getTimestamp() - $responseAt;

            return $age >= 0 && $age < 1800
                ? CredentialAuthorizationAuthority::Allowed
                : CredentialAuthorizationAuthority::Unavailable;
        }

        if ($profile->ownership === CredentialAuthorizationOwnership::Installation
            && ! RolePolicy::canManageInstallationCredentials($user->role)) {
            return CredentialAuthorizationAuthority::Denied;
        }

        if ($user->status !== 'active'
            || in_array($user->managed_membership_status, ['removed', 'disabled'], true)) {
            return CredentialAuthorizationAuthority::Denied;
        }

        return $allowed
            ? CredentialAuthorizationAuthority::Allowed
            : CredentialAuthorizationAuthority::Unavailable;
    }

    /**
     * @param  array<array-key, mixed>  $abilities
     * @return list<string>
     */
    public function canonicalAbilities(array $abilities): array
    {
        if (! array_is_list($abilities)) {
            throw InvalidCredentialInput::malformedAbilities();
        }

        foreach ($abilities as $ability) {
            if (! is_string($ability) || $ability === '') {
                throw InvalidCredentialInput::malformedAbilities();
            }
        }

        OperatorAbility::assertValues($abilities);
        $abilities = array_values(array_unique($abilities));
        sort($abilities, SORT_STRING);

        return $abilities;
    }

    public function label(?string $label): ?string
    {
        if ($label === null) {
            return null;
        }

        $label = trim($label, " \t\n\r\0\x0B");

        if ($label === '' || strlen($label) > 64 || ! mb_check_encoding($label, 'UTF-8') || preg_match('/\p{Cc}/u', $label) === 1) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        return $label;
    }

    private function profile(Request $request, string $appPurpose): CredentialAuthorizationProfile
    {
        if (! $this->declaration instanceof DeclaresCredentialAuthorizationProfiles) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        $profiles = $this->declaration->credentialAuthorizationProfiles($request);

        if (! array_is_list($profiles)) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        foreach ($profiles as $profile) {
            if (! $profile instanceof CredentialAuthorizationProfile) {
                throw InvalidCredentialInput::invalidAppPurposeMapping();
            }
        }

        $matches = array_values(array_filter(
            $profiles,
            static fn (mixed $profile): bool => $profile instanceof CredentialAuthorizationProfile
                && hash_equals($profile->appPurpose, $appPurpose),
        ));

        if (count($matches) !== 1) {
            throw InvalidCredentialInput::invalidAppPurposeMapping();
        }

        return $matches[0];
    }

    private function validate(Request $request, CredentialAuthorizationProfile $profile, string $userId, bool $starting): CredentialPurpose
    {
        if (! hash_equals($profile->appPurpose, $profile->scope->appPurpose)
            || $profile->codeTtlSeconds < 60
            || $profile->codeTtlSeconds > 900
            || $profile->initialPollInterval < 5
            || $profile->initialPollInterval > 30
            || ($profile->expiresAt !== null && ! $profile->expiresAt->isFuture())) {
            throw InvalidCredentialInput::invalidBoundScope();
        }

        $purpose = $this->appPurposes->purpose($profile->appPurpose);

        if (! $purpose->allowedFor(CredentialKind::Bearer, $profile->scope->subject->type)) {
            throw InvalidCredentialInput::purposeNotAllowed();
        }

        $abilities = $this->canonicalAbilities($profile->abilities);

        if ($profile->ownership === CredentialAuthorizationOwnership::Personal) {
            $subject = $this->declaration->resolveSubject($request);

            if ($subject === null
                || $subject->type !== $profile->scope->subject->type
                || ! $this->same($subject->ref, $profile->scope->subject->ref)) {
                throw InvalidCredentialInput::boundScopeMismatch();
            }

            $this->kindPolicy->assertPersonalKindAllowed($profile->scope->subject, CredentialKind::Bearer);

            $declaredAbilities = $this->declaration instanceof DeclaresSelfServiceMintPolicy
                ? $this->canonicalAbilities($this->declaration->selfServiceAbilities($profile->scope->subject))
                : [];

            if ($abilities !== $declaredAbilities) {
                throw InvalidCredentialInput::boundScopeMismatch();
            }
        } else {
            if (! in_array($profile->scope->subject->type, [SubjectType::Application, SubjectType::Installation], true)
                || array_intersect($abilities, OperatorAbility::vocabulary()) !== []) {
                throw InvalidCredentialInput::boundScopeMismatch();
            }

            $this->kindPolicy->assertInstallationKindAllowed($profile->scope->subject, CredentialKind::Bearer);

            if ($starting) {
                $principal = $request->user();
                $role = $principal instanceof User ? $principal->role : null;

                if (! RolePolicy::canManageInstallationCredentials($role)) {
                    throw CredentialAuthorizationRefused::denied();
                }
            }
        }

        if ($userId === '') {
            throw CredentialAuthorizationRefused::denied();
        }

        return $purpose;
    }

    private function same(string $left, mixed $right): bool
    {
        return is_string($right) && hash_equals($left, $right);
    }

    private function timestamp(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof \DateTimeInterface) {
            return $value->getTimestamp();
        }

        try {
            return now()->parse((string) $value)->getTimestamp();
        } catch (\Throwable) {
            return PHP_INT_MIN;
        }
    }
}
