<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * A client identity CLAIMED on a request that presented no working credential.
 *
 * ADVISORY ONLY. The identity is unauthenticated and trivially spoofable — anyone can send any
 * header — so a row here is a signal to look at, never proof that a particular client is present.
 *
 * @property string $id
 * @property string $client_identity
 * @property CarbonInterface|null $first_seen_at
 * @property CarbonInterface|null $last_seen_at
 * @property int $observation_count
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class ClientIdentityObservation extends Model
{
    use HasUuids;

    public $incrementing = false;

    protected $table = 'bfc_client_identity_observations';

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'client_identity',
        'first_seen_at',
        'last_seen_at',
        'observation_count',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'observation_count' => 'integer',
        ];
    }
}
