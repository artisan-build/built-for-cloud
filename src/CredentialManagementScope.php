<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use Illuminate\Database\Eloquent\Builder;

/**
 * A management surface's complete row boundary, applied by every verb that
 * surface exposes.
 */
final readonly class CredentialManagementScope
{
    /**
     * @param  list<string>  $subjectTypes
     * @param  list<string>  $excludedAbilities
     */
    private function __construct(
        private CredentialOwnership $ownership,
        private array $subjectTypes,
        private array $excludedAbilities,
        private ?Subject $subject = null,
        private ?string $userId = null,
        private bool $selfService = false,
    ) {}

    public static function memberInstallation(): self
    {
        return new self(
            CredentialOwnership::Installation,
            [SubjectType::Application->value, SubjectType::Installation->value],
            OperatorAbility::vocabulary(),
        );
    }

    public static function personal(Subject $subject, string $userId): self
    {
        return new self(
            CredentialOwnership::Account,
            [$subject->type->value],
            [],
            $subject,
            $userId,
            true,
        );
    }

    /** @return list<string> */
    public function subjectTypes(): array
    {
        return $this->subjectTypes;
    }

    /**
     * @param  Builder<Credential>  $query
     * @return Builder<Credential>
     */
    public function apply(Builder $query): Builder
    {
        SigningRootMac::excludeReservedFrom($query);

        $this->ownership === CredentialOwnership::Installation
            ? $query->whereNull('user_id')
            : $query->whereNotNull('user_id');

        $query->whereIn('subject_type', $this->subjectTypes);

        if ($this->subject !== null) {
            $query->where('subject_ref', $this->subject->ref);
        }

        if ($this->userId !== null) {
            $query->where('user_id', $this->userId);
        }

        foreach ($this->excludedAbilities as $ability) {
            $query->where(static function (Builder $query) use ($ability): void {
                $query->whereNull('abilities')
                    ->orWhereJsonDoesntContain('abilities', $ability);
            });
        }

        return $query;
    }

    /** @param list<string>|null $abilities */
    public function firstExcludedAbility(?array $abilities): ?string
    {
        return array_values(array_intersect($abilities ?? [], $this->excludedAbilities))[0] ?? null;
    }

    public function assertRotationAllowed(Credential $credential): void
    {
        if (! $this->selfService) {
            return;
        }

        $declaration = app(CredentialDeclaration::class);
        $kinds = $declaration instanceof DeclaresSelfServiceMintPolicy
            ? $declaration->selfServiceKinds($credential->subject())
            : [CredentialKind::Bearer];

        if (! in_array($credential->kind, $kinds, true)) {
            throw CredentialVerbRefused::selfServiceKind($credential->kind);
        }

        $abilities = array_values(array_filter(
            $declaration instanceof DeclaresSelfServiceMintPolicy
                ? $declaration->selfServiceAbilities($credential->subject())
                : [],
            static fn (string $ability): bool => trim($ability) !== '',
        ));

        foreach ($credential->abilities ?? [] as $ability) {
            if (! in_array($ability, $abilities, true)) {
                throw CredentialVerbRefused::abilityWidening($ability);
            }
        }
    }
}
