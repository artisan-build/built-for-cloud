<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Database\Factories\ApiTokenFactory;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $name
 * @property string $token_hash
 * @property CarbonInterface|null $last_used_at
 * @property int $request_count
 * @property CarbonInterface|null $expires_at
 * @property CarbonInterface|null $revoked_at
 * @property CarbonInterface|null $rotated_at
 * @property array<int, string>|null $abilities
 * @property SubjectType|null $subject_type
 * @property string|null $subject_ref
 * @property string|null $client_identity
 * @property CarbonInterface|null $client_identity_last_seen_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 *
 * @method static ApiTokenFactory factory($count = null, $state = [])
 */
final class ApiToken extends Model
{
    /** @use HasFactory<ApiTokenFactory> */
    use HasFactory;

    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'name',
        'token_hash',
        'last_used_at',
        'request_count',
        'expires_at',
        'revoked_at',
        'rotated_at',
        'abilities',
        'subject_type',
        'subject_ref',
        'client_identity',
        'client_identity_last_seen_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'rotated_at' => 'datetime',
            'request_count' => 'integer',
            'abilities' => 'array',
            'subject_type' => SubjectType::class,
            'client_identity_last_seen_at' => 'datetime',
        ];
    }

    public function hasAbility(string $ability): bool
    {
        if ($this->abilities === null || $this->abilities === []) {
            return false;
        }

        return in_array($ability, $this->abilities, true);
    }

    public function hasScope(Scope $scope): bool
    {
        return $this->hasAbility($scope->value);
    }

    /**
     * The row's declared subject, or null when the row predates subjects
     * (declare-don't-guess: a legacy row is never retro-classified). A
     * subject identifies what a revocation costs; it never authenticates
     * or authorizes anything.
     */
    public function subject(): ?Subject
    {
        if ($this->subject_type === null || $this->subject_ref === null) {
            return null;
        }

        return new Subject($this->subject_type, $this->subject_ref);
    }

    /**
     * The instance-reported status (PRD 1.5): `revoked` wins over expiry
     * because revocation is the deliberate act; the expiry boundary matches
     * `scopeResolvable` (a row expiring exactly now no longer resolves).
     * Every `api_tokens` row structurally carries the usage signal, so
     * {@see ReportedStatus::Unknown} is never produced here — see that
     * enum for why the case exists anyway.
     */
    public function reportedStatus(): ReportedStatus
    {
        if ($this->revoked_at !== null) {
            return ReportedStatus::Revoked;
        }

        if ($this->expires_at !== null && ! $this->expires_at->isAfter(now())) {
            return ReportedStatus::Expired;
        }

        return ReportedStatus::Active;
    }

    /**
     * @param  Builder<ApiToken>  $query
     * @return Builder<ApiToken>
     */
    public function scopeResolvable(Builder $query): Builder
    {
        return $query->where(function (Builder $query): void {
            $query->whereNull('expires_at')
                ->orWhere('expires_at', '>', now());
        });
    }

    protected static function newFactory(): ApiTokenFactory
    {
        return ApiTokenFactory::new();
    }
}
