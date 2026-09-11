<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Throwable;

/**
 * @property string $id
 * @property string $initiated_by_user_id
 * @property ManagedTransitionDirection $direction
 * @property ManagedTransitionStatus $status
 * @property string $issuer
 * @property string $connection_id
 * @property string $organization_id
 * @property string $installation_id
 * @property string $authority_base_url
 * @property string|null $authority_ca_bundle
 * @property string $client_credential_reference
 * @property string $mode_before
 * @property string $mode_after
 * @property int $generation_before
 * @property int $generation_after
 * @property string $transition_request_id
 * @property string|null $transition_id
 * @property int|null $roster_version
 * @property string|null $roster_cutoff_at
 * @property int|null $roster_total
 * @property int $roster_pages_received
 * @property int $roster_members_received
 * @property string|null $next_roster_cursor
 * @property string|null $local_commit_receipt
 * @property string|null $authority_acknowledged_at
 * @property string $prepare_request_body
 * @property string $prepare_body_digest
 * @property string|null $stage_idempotency_key
 * @property string|null $stage_request_body
 * @property string|null $stage_body_digest
 * @property string|null $ack_idempotency_key
 * @property string|null $ack_request_body
 * @property string|null $ack_body_digest
 * @property string|null $abandon_idempotency_key
 * @property string|null $abandon_request_body
 * @property string|null $abandon_body_digest
 */
final class ManagedTransition extends Model
{
    use HasUuids;

    protected $table = 'bfc_managed_transitions';

    public $incrementing = false;

    protected $keyType = 'string';

    /** @var list<string> */
    protected $guarded = ['active_installation_slot'];

    /** @var list<string> */
    protected $hidden = [
        'active_installation_slot',
        'prepare_request_body',
        'prepare_body_digest',
        'stage_idempotency_key',
        'stage_request_body',
        'stage_body_digest',
        'ack_idempotency_key',
        'ack_request_body',
        'ack_body_digest',
        'abandon_idempotency_key',
        'abandon_request_body',
        'abandon_body_digest',
    ];

    /** @return array<string, mixed> */
    protected function casts(): array
    {
        return [
            'direction' => ManagedTransitionDirection::class,
            'status' => ManagedTransitionStatus::class,
            'generation_before' => 'integer',
            'generation_after' => 'integer',
            'roster_version' => 'integer',
            'roster_total' => 'integer',
            'roster_pages_received' => 'integer',
            'roster_members_received' => 'integer',
        ];
    }

    /** @param array<string, mixed> $attributes */
    public static function createActive(array $attributes): self
    {
        try {
            return self::query()->create($attributes);
        } catch (QueryException $exception) {
            for ($current = $exception; $current instanceof Throwable; $current = $current->getPrevious()) {
                if (str_contains($current->getMessage(), 'bfc_transition_active_slot_unique')
                    || str_contains($current->getMessage(), 'active_installation_slot')) {
                    throw new ManagedAuthRefused('transition_in_progress', previous: $exception);
                }
            }

            throw $exception;
        }
    }
}
