<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\OutboxDrainer;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use LogicException;

/**
 * **AN IMMUTABLE DEDUP LEDGER**, one row per app-action event, written in
 * the SAME database transaction as the event and the action it records.
 *
 * The table is named for the outbox PATTERN D17 names, and the pattern is
 * what the WRITE side does — same-transaction insert, consumed later. But
 * calling the thing an outbox would claim the delivery half, and there is
 * no delivery half: nothing drains it, nothing marks it, nothing reads
 * it. What ships is a ledger, and it is described as one so that a reader
 * of the schema is not told there is machinery behind it.
 *
 * **WHY IT IS A ROW AND NOT A COLUMN.** `dedup_key` is UNIQUE, and that
 * index is what makes "exactly one event per action" a database property
 * rather than a convention: a second emission of the same logical action
 * fails this insert and takes the whole transaction with it — the action
 * and its first event included. `event_id` is unique too, so "one ledger
 * row per event" is a database property as well and neither half of the
 * pair can be quietly doubled.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a second
 *   emission of the same logical action, and takes the transaction with
 *   it", "refuses a second ledger row for one event" and "writes the
 *   event and its ledger row in the caller's own transaction".
 *
 * **IT IS PROTECTED EXACTLY AS STRONGLY AS THE EVENT IT DEDUPES, and it
 * has to be.** A dedup record that can be deleted is not a dedup record:
 * a unique index only rejects a duplicate while the row it collides with
 * still exists, so a deletable ledger row means the duplicate this
 * stream promises to refuse can be re-admitted by removing the evidence
 * of the first one. So the same three layers the event carries are here
 * too — model events on `updating` and `deleting`, the ten enumerated
 * bulk spellings refused by {@see AppendOnlyBuilder}, and database
 * triggers aborting raw row-level UPDATE and DELETE on the three drivers
 * this package writes them for — with the same residue
 * {@see AppActionEvent} names: raw TRUNCATE is DDL, a raw INSERT fires
 * no model events, an unknown driver has no triggers, and DDL privilege
 * defeats all of it.
 *   Pinned by `tests/AppActionAuditTest.php` — "rejects update and
 *   delete on a ledger row at the model layer", "refuses every
 *   enumerated bulk mutation on the app-action stream, on both models"
 *   and "rejects raw update and delete on the ledger table at the
 *   database layer on sqlite".
 *
 * **`dedup_key` IS A DIGEST, NEVER A CALLER'S STRING.**
 * {@see AppActionRecorder} hashes the caller's natural key together with
 * the action's vocabulary and name, so nothing an app supplies is stored
 * verbatim — the column would otherwise be a 255-character content
 * channel into a stream whose entire premise (D15) is that no app
 * content enters it — and two unrelated vocabularies that happen to
 * choose the same natural key cannot silently suppress each other. The
 * model refuses any row whose key is not that digest's shape.
 *   Pinned by `tests/AppActionAuditTest.php` — "stores a digest rather
 *   than the caller's natural key", "namespaces the digest by vocabulary
 *   and action, so two vocabularies sharing a natural key do not
 *   collide" and "refuses a ledger row whose dedup key is not a digest".
 *
 * **NO DRAINER SHIPS FOR THIS STREAM, and no columns pretend one does.**
 * {@see CredentialOutboxEntry} carries `attempts`, `claimed_at`,
 * `claim_token`, `delivered_at`, `delivered_recipients` and
 * `last_error`, because {@see OutboxDrainer} writes every one of them.
 * Here they would be six columns no code sets — a schema making promises
 * about delivery bookkeeping that nothing keeps, which is the same
 * defect as a docblock doing it. They arrive with the consumer that
 * needs them.
 *
 * **WHAT THIS LEDGER IS NOT, corrected from an earlier revision of this
 * docblock that claimed both.** It is not the replayable history — the
 * EVENT table is append-only and complete, so a future consumer can be
 * built against it without this table existing at all, and "a migration
 * over history nobody can replay" was never the argument for keeping
 * this one. And it is not an ORDERED hand-off: the only ordering it
 * carries is a `created_at` at one-second resolution, which is nullable,
 * so it cannot sequence two rows written in the same second. The honest
 * statement of what it gives is dedup, durably, and nothing else.
 *
 * **STORAGE IS UNBOUNDED.** One row per app-action event, forever,
 * pruned by nothing — the same declared retention the event table
 * carries, and the cost is named here rather than discovered later.
 *
 * @property string $id
 * @property string $event_id
 * @property string $dedup_key
 * @property CarbonInterface|null $created_at
 */
final class AppActionOutboxEntry extends Model
{
    use HasUuids;

    public const UPDATED_AT = null;

    /** sha256, hex — the shape {@see AppActionRecorder} produces and the only shape this table stores. */
    public const string DEDUP_KEY_PATTERN = '/^[0-9a-f]{64}$/D';

    protected $table = 'bfc_app_action_outbox';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'event_id',
        'dedup_key',
    ];

    /**
     * Refuse a ledger row that would break the ledger's own invariants,
     * whoever is writing it — the same stance {@see AppActionEvent}
     * takes, for the same reason: {@see AppActionRecorder} is the only
     * path this package offers, and it is not a gate PHP can close.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws LogicException
     */
    public static function assertWellFormed(array $attributes): void
    {
        $eventId = $attributes['event_id'] ?? null;

        if (! is_string($eventId) || $eventId === '') {
            throw new LogicException('A ledger row names the app-action event it dedupes.');
        }

        $key = $attributes['dedup_key'] ?? null;

        if (! is_string($key) || preg_match(self::DEDUP_KEY_PATTERN, $key) !== 1) {
            throw new LogicException(
                'A dedup key is a sha256 digest of the action and its natural key, never a caller\'s string.',
            );
        }
    }

    protected static function booted(): void
    {
        self::creating(function (AppActionOutboxEntry $entry): void {
            self::assertWellFormed($entry->getAttributes());
        });

        self::updating(function (): never {
            throw new LogicException('The app-action dedup ledger is append-only: rows are never updated.');
        });

        self::deleting(function (): never {
            throw new LogicException('The app-action dedup ledger is append-only: rows are never deleted.');
        });
    }

    /**
     * @param  Builder  $query
     */
    public function newEloquentBuilder($query): AppActionLedgerBuilder
    {
        return new AppActionLedgerBuilder($query);
    }
}
