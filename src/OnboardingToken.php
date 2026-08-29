<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string|null $email
 * @property string $scope
 * @property string $token_hash
 * @property string|null $durable_token_id
 * @property DurableStore|null $durable_store
 * @property CarbonInterface|null $consumed_at
 * @property bool $console_key_authority
 * @property CarbonInterface|null $console_key_filed_at
 * @property CarbonInterface $expires_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class OnboardingToken extends Model
{
    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * Deliberately WITHOUT `console_key_authority` and
     * `console_key_filed_at` (rework B1). Key-custody authority is set
     * server-side by the admin-gated issue verb through `forceFill`, and
     * spent server-side by the exchange — exactly the discipline
     * `api_tokens.rotated_at` uses, and for the same reason: an
     * authority that request input can mass-assign is not an authority.
     *
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'email',
        'scope',
        'token_hash',
        'durable_token_id',
        'durable_store',
        'consumed_at',
        'expires_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'durable_store' => DurableStore::class,
            'consumed_at' => 'datetime',
            'console_key_authority' => 'boolean',
            'console_key_filed_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * The store the linked durable was minted into. NULL backfills to
     * `api_tokens` — the only store that existed before the seam toggle —
     * so a pre-toggle linkage is never re-interpreted by whatever the
     * CURRENT declaration targets.
     */
    public function durableStore(): DurableStore
    {
        return $this->durable_store ?? DurableStore::ApiTokens;
    }

    /**
     * Whether this code may carry a countersigning-key delivery RIGHT
     * NOW (Console PRD D12, rework B1): it was issued with the explicit
     * authority, and has not already spent it.
     *
     * Read inside the exchange's locked transaction, never cached — the
     * whole point of the second clause is that one authorized code files
     * one key, whatever its burn mode allows about re-presentation.
     */
    public function mayFileConsoleKey(): bool
    {
        return $this->console_key_authority && $this->console_key_filed_at === null;
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public static function resolve(string $plainTextToken): ?self
    {
        /** @var self|null $token */
        $token = self::query()
            ->pending()
            ->where('token_hash', self::hashToken($plainTextToken))
            ->first();

        return $token;
    }

    /**
     * @param  Builder<OnboardingToken>  $query
     * @return Builder<OnboardingToken>
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->whereNull('consumed_at')
            ->where('expires_at', '>', now());
    }
}
