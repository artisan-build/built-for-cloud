<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * One row in the instance-side, append-only audit stream (PRD 1.9 / D8).
 *
 * Ids only — never secret values, never hashes. The model throws on any
 * update or delete; database triggers (where the driver permits) abort raw
 * query-builder mutations too. History is corrected by appending a new row
 * that supersedes a wrong one, never by editing.
 *
 * `note` and `reason_code` are customer-visible (D7): `note` is stored
 * verbatim and bounded; every renderer escapes it, and every export path
 * runs it through {@see CsvFieldSanitizer}.
 *
 * @property string $id
 * @property LifecycleEventType $event
 * @property string|null $code_id
 * @property string|null $credential_id
 * @property string|null $superseded_by_credential_id
 * @property string|null $provider
 * @property string|null $deployment
 * @property string|null $environment
 * @property AuditActorType|null $actor_type
 * @property string|null $actor_ref
 * @property string|null $recipient
 * @property int|null $code_ttl_seconds
 * @property CarbonInterface|null $credential_expires_at
 * @property AuditReason|null $reason_code
 * @property string|null $note
 * @property CarbonInterface $occurred_at
 * @property CarbonInterface|null $created_at
 */
final class CredentialAuditEvent extends Model
{
    use HasUuids;

    public const UPDATED_AT = null;

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'event',
        'code_id',
        'credential_id',
        'superseded_by_credential_id',
        'provider',
        'deployment',
        'environment',
        'actor_type',
        'actor_ref',
        'recipient',
        'code_ttl_seconds',
        'credential_expires_at',
        'reason_code',
        'note',
        'occurred_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'event' => LifecycleEventType::class,
            'actor_type' => AuditActorType::class,
            'reason_code' => AuditReason::class,
            'code_ttl_seconds' => 'integer',
            'credential_expires_at' => 'datetime',
            'occurred_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        self::updating(function (): never {
            throw new LogicException('The credential audit stream is append-only: rows are never updated.');
        });

        self::deleting(function (): never {
            throw new LogicException('The credential audit stream is append-only: rows are never deleted.');
        });
    }
}
