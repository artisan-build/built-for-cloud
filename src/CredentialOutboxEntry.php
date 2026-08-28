<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * A pending delivery in the transactional outbox. Committed with the state
 * transition it announces; drained after commit by {@see OutboxDrainer}.
 *
 * `last_error` only ever carries an exception CLASS name: a driver or
 * mailer message can echo bound values, and this column is operator-visible.
 *
 * @property string $id
 * @property string $audit_event_id
 * @property string $dedup_key
 * @property int $attempts
 * @property CarbonInterface|null $claimed_at
 * @property CarbonInterface|null $delivered_at
 * @property string|null $last_error
 * @property CarbonInterface|null $created_at
 */
final class CredentialOutboxEntry extends Model
{
    use HasUuids;

    public const UPDATED_AT = null;

    protected $table = 'credential_outbox';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'audit_event_id',
        'dedup_key',
        'attempts',
        'claimed_at',
        'delivered_at',
        'last_error',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'attempts' => 'integer',
            'claimed_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }

    /**
     * Rows a drain may take: undelivered, and either unclaimed or claimed
     * long enough ago that the claiming consumer is presumed dead. A
     * consumer that dies mid-delivery leaves its row here, claimable again
     * once the claim goes stale.
     *
     * @param  Builder<CredentialOutboxEntry>  $query
     * @return Builder<CredentialOutboxEntry>
     */
    public function scopeClaimable(Builder $query, int $claimTtlSeconds): Builder
    {
        return $query
            ->whereNull('delivered_at')
            ->where(function (Builder $query) use ($claimTtlSeconds): void {
                $query->whereNull('claimed_at')
                    ->orWhere('claimed_at', '<=', now()->subSeconds($claimTtlSeconds));
            });
    }
}
