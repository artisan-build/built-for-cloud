<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Database\Factories\ApiTokenFactory;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

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

    /**
     * A subject is declared as a PAIR or not at all: `subject_type` and
     * `subject_ref` together, or both null (the legacy shape). A partial
     * pair would silently map to null in subject() and inherit legacy
     * authority under a tenant-scoped matrix — refused at the model, the
     * package's enforcement point (the same stance as the credentials
     * store's public-key rule).
     */
    protected static function booted(): void
    {
        self::saving(function (ApiToken $token): void {
            if (($token->subject_type === null) !== ($token->subject_ref === null)) {
                throw new InvalidArgumentException(
                    'A subject is declared as a pair: subject_type and subject_ref together, or both null (legacy).',
                );
            }
        });
    }

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
     * The row's declared subject, or null when the row predates subjects —
     * BOTH columns null is the one shape that means legacy
     * (declare-don't-guess: a legacy row is never retro-classified). A
     * subject identifies what a revocation costs; it never authenticates
     * or authorizes anything.
     *
     * A partial pair cannot be written through the model (the saving hook
     * throws); the null-if-either-null mapping stays as defence against a
     * raw write, so a half-declared subject can never masquerade as a
     * declared one.
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
     *
     * One anomaly class, named honestly: a row with `revoked_at` set but
     * no effective expiry (an import, a manual repair) reports `revoked`
     * here while legacy resolution — which ignores `revoked_at`,
     * test-pinned — still authenticates it. No package verb can produce
     * or leave behind that state any more (`revoke()`/`revokeById()` both
     * stamp expiry), and `revokeById()` repairs it on contact.
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
