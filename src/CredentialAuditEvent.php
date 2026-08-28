<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use LogicException;

/**
 * One row in the instance-side, append-only audit stream (PRD 1.9 / D8).
 *
 * Ids only — never secret values, never hashes. The model throws on any
 * update, delete, or truncate (static and query-builder paths — see
 * {@see CredentialAuditEventBuilder}); database triggers (where the driver
 * permits) abort raw row-level UPDATE/DELETE too. History is corrected by
 * appending a new row that supersedes a wrong one, never by editing.
 *
 * THE ENFORCEMENT BOUNDARY, stated like the store's public-key rule: this
 * model is the package's enforcement point, and every framework code path
 * mutates nothing through it. Raw `DB::table(...)` writes are caught only
 * where the driver's triggers exist; raw `TRUNCATE TABLE` SQL and
 * privileged console/schema access are OUTSIDE the package's reach —
 * TRUNCATE and DROP enforcement, where an operator wants it, is a
 * database-privilege matter (revoke DDL from the app's connection), not a
 * model guard.
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

    /**
     * @param  Builder  $query
     */
    public function newEloquentBuilder($query): CredentialAuditEventBuilder
    {
        return new CredentialAuditEventBuilder($query);
    }
}
