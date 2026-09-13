<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

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
    ) {}

    public static function memberInstallation(): self
    {
        return new self(
            CredentialOwnership::Installation,
            [SubjectType::Application->value, SubjectType::Installation->value],
            OperatorAbility::vocabulary(),
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
        $this->ownership === CredentialOwnership::Installation
            ? $query->whereNull('user_id')
            : $query->whereNotNull('user_id');

        $query->whereIn('subject_type', $this->subjectTypes);

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
}
