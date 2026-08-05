<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string|null $owner_token_id
 * @property string|null $notify_callback
 * @property string|null $webhook_secret
 * @property string|null $pending_claim_id
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class Ownership extends Model
{
    use HasUuids;

    protected $table = 'ownership';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'owner_token_id',
        'notify_callback',
        'webhook_secret',
        'pending_claim_id',
    ];

    public static function current(): ?self
    {
        /** @var self|null $ownership */
        $ownership = self::query()->first();

        return $ownership;
    }
}
