<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $token_hash
 * @property CarbonInterface|null $consumed_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class OwnershipClaim extends Model
{
    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'token_hash',
        'consumed_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'consumed_at' => 'datetime',
        ];
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public static function resolve(string $plainTextToken): ?self
    {
        /** @var self|null $claim */
        $claim = self::query()
            ->pending()
            ->where('token_hash', self::hashToken($plainTextToken))
            ->first();

        return $claim;
    }

    /**
     * @param  Builder<OwnershipClaim>  $query
     * @return Builder<OwnershipClaim>
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->whereNull('consumed_at');
    }
}
