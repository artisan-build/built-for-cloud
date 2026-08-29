<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\OutboxDrainer;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * The app-action stream's transactional outbox: one row per event,
 * inserted in the SAME transaction as the event and the action it
 * announces (Console PRD D17 — "reusing the outbox PATTERN").
 *
 * **IT EARNS ITS PLACE TWICE, and only one of the two is about
 * delivery.** `dedup_key` is UNIQUE, and that index is what makes
 * "exactly one event per action" a database property rather than a
 * convention: a second emission of the same logical action fails this
 * insert and takes the whole transaction with it — the action and its
 * first event included — which is the shape the credential stream
 * already ships and the shape a duplicate ought to have. The second is
 * that a future consumer of this stream needs a durable, ordered,
 * at-least-once hand-off point, and adding one after the fact would mean
 * a migration over history nobody can replay.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a second
 *   emission of the same logical action, and takes the transaction with
 *   it" and "writes the event and its outbox row in the caller's own
 *   transaction".
 *
 * **THERE IS NO DRAINER FOR THIS STREAM IN THIS RELEASE, AND THAT IS
 * DELIBERATE.** Nothing consumes app-action events yet — there is no
 * read transport, no notification, and no vendor-side sink — so a
 * drainer would have nowhere to deliver to, and a delivery mechanism
 * that delivers nowhere is theatre that later has to be unpicked. The
 * rows accumulate, claimable by whatever consumer eventually exists.
 * {@see OutboxDrainer} is the CREDENTIAL stream's drainer and does not
 * touch this table.
 *
 * **AND THE COLUMNS NOTHING WRITES ARE ABSENT, for the same reason.**
 * {@see CredentialOutboxEntry} carries `attempts`, `claimed_at`,
 * `claim_token`, `delivered_at`, `delivered_recipients` and
 * `last_error`, because it has a consumer that writes every one of them.
 * Copying that shape here would ship six columns no code sets — a schema
 * making a promise about delivery bookkeeping nothing keeps, which is
 * the same defect as a docblock doing it. They arrive with the consumer
 * that needs them.
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
}
