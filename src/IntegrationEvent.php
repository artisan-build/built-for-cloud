<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Every integration event ever DECIDED — applied or
 * acknowledged-and-ignored — keyed uniquely on (namespace, event id) so a
 * replayed event answers idempotently: same response shape, no second
 * invitation, no state change (SEC-V3-05). `event_kind` keeps the record
 * generic for the offboarding verb's events.
 *
 * @property string $id
 * @property string $integration_namespace
 * @property string $event_id
 * @property string $external_subject
 * @property string $event_kind
 * @property int $entitlement_version
 * @property bool $applied
 * @property string|null $invitation_id
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class IntegrationEvent extends Model
{
    use HasUuids;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'integration_namespace',
        'event_id',
        'external_subject',
        'event_kind',
        'entitlement_version',
        'applied',
        'invitation_id',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'entitlement_version' => 'integer',
            'applied' => 'boolean',
        ];
    }
}
