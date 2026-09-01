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
 * **THE DEDUP LEDGER.** For each successful {@see AppActionRecorder}
 * emission, one event row and one row here are inserted in the SAME
 * database transaction as the action they record only when the action
 * and these default-connection audit models share a connection. The
 * recorder does not select or compare the action's connection; arranging
 * that precondition is the consumer's responsibility. The package never
 * updates or prunes either row; app-owned direct writes and deletions can
 * still make the pair incomplete, which the residue below states in full.
 *
 * The table is named for the outbox PATTERN D17 names, and the pattern is
 * what the WRITE side does — same-connection, same-transaction insert,
 * consumed later. But calling the thing an outbox would claim the delivery
 * half, and there is no delivery half: nothing drains it, nothing marks it,
 * nothing reads it. What ships is a ledger, and it is described as one so
 * that a reader of the schema is not told there is machinery behind it.
 *
 * **WHY IT IS A ROW AND NOT A COLUMN.** `dedup_key` is UNIQUE, and that
 * index is what makes one event per CALLER-IDENTIFIED action hold of
 * what {@see AppActionRecorder} writes: a second emission of the same
 * logical action fails this insert and takes the whole transaction with
 * it — the action and its first event included. **Caller-identified is
 * the condition and not decoration**: a `record()` call that supplies no
 * natural key is keyed to the new event's own id, so it collides with
 * nothing, and two such calls for one logical action both succeed.
 * {@see AppActionRecorder::record()} states it in full. `event_id` is unique too, so one
 * recorder call cannot leave two ledger rows behind. Both are database
 * properties of the ROWS THAT EXIST; neither makes an event that was
 * written without going through the recorder acquire a ledger row, and
 * an event with no ledger row is deduped by nothing.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a second
 *   emission of the same logical action, and takes the transaction with
 *   it", "refuses a second ledger row for one event" and "persists a
 *   well-formed direct model write with no ledger row, which is the
 *   residue the recorder names".
 *
 * **IT IS PROTECTED AS STRONGLY AS THE EVENT IT DEDUPES, and it has to
 * be.** A dedup record that can be deleted is not a dedup record: a
 * unique index only rejects a duplicate while the row it collides with
 * still exists, so a deletable ledger row would let the duplicate this
 * stream refuses be re-admitted by removing the evidence of the first
 * one. The same three layers the event carries are here — model events
 * on `updating` and `deleting`, the enumerated bulk spellings refused by
 * {@see AppendOnlyBuilder}, and database triggers aborting raw row-level
 * UPDATE and DELETE on the three drivers this package writes them for.
 *
 * **AS STRONGLY, INCLUDING THE RESIDUE**, which {@see AppActionEvent}
 * states in full and which is not a footnote: none of the three layers
 * is a boundary. Raw TRUNCATE is DDL, a raw INSERT and the quiet model
 * methods fire no model events, the builder's list is a fixed
 * enumeration of names, an unknown driver has no triggers, and DDL
 * privilege defeats all of it. An app can delete this row from its own
 * database and the package will neither prevent nor notice it.
 *   Pinned by `tests/AppActionAuditTest.php` — "rejects update and
 *   delete on a ledger row at the model layer", "refuses every
 *   enumerated bulk mutation on the app-action stream, on both models"
 *   and "rejects raw update and delete on the ledger table at the
 *   database layer on sqlite".
 *
 * **`dedup_key` IS A DIGEST OF THE CALLER'S KEY, NOT THE KEY.**
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
 *   collide" and "refuses a ledger row whose dedup key is not
 *   digest-shaped, and accepts one that merely looks like a digest".
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
 * EVENT table is the one a future consumer would be built against,
 * without this table existing at all: it carries every emission the
 * recorder makes and the package prunes none of them, which is as much
 * as any table in a consuming app's own database can be said to hold.
 * And "a migration
 * over history nobody can replay" was never the argument for keeping
 * this one. And it is not an ORDERED hand-off: the only ordering it
 * carries is a `created_at` at one-second resolution, which is nullable,
 * so it cannot sequence two rows written in the same second. The honest
 * statement of what it gives is dedup, durably, and nothing else.
 *
 * **STORAGE IS UNBOUNDED.** One row per recorder emission, and **nothing
 * in this package ever prunes one** — the same declared retention the
 * event table carries, and the cost is named here rather than discovered
 * later. "Forever" is the package's half of it only: an app can delete
 * its own rows, as the residue above says.
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

    /**
     * sha256, hex — the shape {@see AppActionRecorder} produces, and the
     * shape `creating` additionally requires of the writes that fire it.
     * **The TABLE enforces only 64 characters and uniqueness**, so an
     * event-free insert can store sixty-four `z`s.
     */
    public const string DEDUP_KEY_PATTERN = '/^[0-9a-f]{64}$/D';

    protected $table = 'bfc_app_action_outbox';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'event_id',
        'dedup_key',
    ];

    /**
     * Refuse a ledger row that would break the ledger's own invariants —
     * **defence in depth on the writes that fire `creating`, and not a
     * boundary**, exactly as {@see AppActionEvent::assertWellFormed()}
     * is.
     *
     * The dedup-key check is a good example of why no claim may rest on
     * it: it verifies the SHAPE of a sha256 digest, so sixty-four
     * literal `a` characters satisfy it. It cannot verify that a key IS
     * the digest of anything, because the natural key it would need is
     * the caller's and is not stored — deliberately, since storing it is
     * the app-content channel this column exists to avoid. What makes a
     * key a real digest is that {@see AppActionRecorder::dedupKeyFor()}
     * computed it; this check catches a caller that put a slug there by
     * hand.
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
                'A dedup key is the sha256 digest AppActionRecorder computes, not a caller\'s string.',
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
