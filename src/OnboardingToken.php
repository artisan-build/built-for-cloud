<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $email
 * @property string $scope
 * @property string $token_hash
 * @property string|null $durable_token_id
 * @property CarbonInterface|null $consumed_at
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
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'email',
        'scope',
        'token_hash',
        'durable_token_id',
        'consumed_at',
        'expires_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'consumed_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
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
