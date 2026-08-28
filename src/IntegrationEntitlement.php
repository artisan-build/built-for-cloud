<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * The latest ACCEPTED entitlement version per (integration namespace,
 * external subject) — the SEC-V3-05 ordering gate's lock point. A verb
 * carrying an integration event locks this row for update and
 * transactionally ignores any event whose version is not newer, so a
 * delayed `sponsorship_created` arriving after `sponsorship_cancelled`
 * cannot silently reopen access. Event-kind generic: invite today, the
 * offboarding verb later, one gate.
 *
 * @property string $id
 * @property string $integration_namespace
 * @property string $external_subject
 * @property int $entitlement_version
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class IntegrationEntitlement extends Model
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
        'external_subject',
        'entitlement_version',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'entitlement_version' => 'integer',
        ];
    }
}
