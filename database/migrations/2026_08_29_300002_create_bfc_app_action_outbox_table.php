<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The app-action stream's DEDUP LEDGER (Console PRD D17): for each
 * successful `AppActionRecorder` emission, one row here and one event
 * row, inserted in the SAME transaction as the action they record only
 * when the action and the default-connection audit models share a
 * connection. The recorder does not select or compare the action's
 * connection; arranging that precondition is the consumer's
 * responsibility. Nothing in the package updates or prunes either row;
 * an app writing or deleting its own rows can still make the pair
 * incomplete, which the limits below state in full.
 *
 * The table is named for the outbox PATTERN D17 names, and the pattern is
 * what the write side does. The delivery half does not exist — nothing
 * drains this, nothing marks it, nothing reads it — so what ships is a
 * ledger, and the model's docblock says so rather than letting the name
 * claim machinery that is not here.
 *
 * A separate table rather than a column on the event row, for the reason
 * the credential outbox already gives: the event row is append-only by
 * construction, and delivery state — when a consumer eventually writes
 * any — is mutable bookkeeping that must not live on an immutable
 * record.
 *
 * TWO UNIQUE INDEXES, and both are load-bearing:
 *
 *  - `dedup_key` is the whole of "one event per caller-identified
 *    action" — for what `AppActionRecorder` writes, which is where that
 *    guarantee lives, and only for calls that supply a natural key: a
 *    call that supplies none is keyed to the new event's own id and
 *    collides with nothing. A second emission of the same logical action
 *    fails this insert and takes the transaction with it. It stores a sha256 digest
 *    of the action's vocabulary, its name and the caller's natural key —
 *    never the caller's own string, which in a wide column would have
 *    been an app-content channel into a stream whose premise (D15) is
 *    that no app content enters it. An event written without going
 *    through the recorder has no row here at all, and is deduped by
 *    nothing.
 *  - `event_id` makes "one ledger row per event" a database property
 *    too, so one recorder call cannot leave two rows behind.
 *
 * AND IT IS APPEND-ONLY, as strongly as the event it dedupes. That is
 * not symmetry for its own sake: a unique index only rejects a duplicate
 * while the row it collides with still EXISTS, so a deletable ledger row
 * would let the duplicate this stream refuses be re-admitted by deleting
 * the evidence of the first one. The model throws on update and delete,
 * the shared builder refuses an enumerated set of bulk spellings, and —
 * where the driver permits — the triggers below abort raw row-level
 * UPDATE and DELETE.
 *
 * As strongly INCLUDING THE LIMITS, which are the event table's and are
 * not footnotes: TRUNCATE is DDL and no row trigger sees it; a raw
 * INSERT and the quiet model methods fire no model events; the builder's
 * list is a fixed enumeration of names and a spelling not on it forwards
 * straight through; an unknown driver (sqlsrv) gets model-level
 * enforcement only; and a connection with schema access can DROP any of
 * it. An app can delete its own rows and the package will neither
 * prevent nor notice it. Append-only here is a strong convention with
 * tripwires under it, not a cryptographic property.
 *
 * WHAT IS NOT HERE, and why. The credential outbox carries `attempts`,
 * `claimed_at`, `claim_token`, `delivered_at`, `delivered_recipients`
 * and `last_error`, because a drainer writes every one of them. This
 * stream has no consumer in this release, so those columns would be six
 * promises about delivery bookkeeping that no code keeps. They arrive
 * with the consumer that needs them, in its own migration — and, being
 * mutable, that consumer will have to decide where they can live given
 * this table is append-only.
 *
 * STORAGE IS UNBOUNDED: one row per recorder emission, pruned by nothing
 * in this package. An app deleting its own rows is outside what the
 * package can see.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_app_action_outbox', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('event_id')->unique();
            // 64 hex characters: the sha256 the recorder produces, and
            // the shape the model additionally requires on the writes
            // that fire `creating`. The column itself enforces only
            // width and uniqueness. Sized to the digest rather than left
            // at 255 so it cannot hold prose even when something
            // bypasses the model.
            $table->string('dedup_key', 64)->unique();
            $table->timestamp('created_at')->nullable();
        });

        match (Schema::getConnection()->getDriverName()) {
            'sqlite' => $this->guardSqlite(),
            'mysql', 'mariadb' => $this->guardMysql(),
            'pgsql' => $this->guardPgsql(),
            default => null,
        };
    }

    public function down(): void
    {
        if (Schema::getConnection()->getDriverName() === 'pgsql' && Schema::hasTable('bfc_app_action_outbox')) {
            DB::statement('DROP TRIGGER IF EXISTS bfc_app_action_outbox_append_only ON bfc_app_action_outbox');
            DB::statement('DROP FUNCTION IF EXISTS bfc_app_action_outbox_reject_mutation()');
        }

        // sqlite and mysql triggers drop with the table.
        Schema::dropIfExists('bfc_app_action_outbox');
    }

    private function guardSqlite(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_outbox_no_update
            BEFORE UPDATE ON bfc_app_action_outbox
            BEGIN
                SELECT RAISE(ABORT, 'bfc_app_action_outbox is append-only');
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_outbox_no_delete
            BEFORE DELETE ON bfc_app_action_outbox
            BEGIN
                SELECT RAISE(ABORT, 'bfc_app_action_outbox is append-only');
            END
            SQL);
    }

    private function guardMysql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_outbox_no_update
            BEFORE UPDATE ON bfc_app_action_outbox
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bfc_app_action_outbox is append-only'
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_outbox_no_delete
            BEFORE DELETE ON bfc_app_action_outbox
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bfc_app_action_outbox is append-only'
            SQL);
    }

    private function guardPgsql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION bfc_app_action_outbox_reject_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'bfc_app_action_outbox is append-only';
            END;
            $$ LANGUAGE plpgsql
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_outbox_append_only
            BEFORE UPDATE OR DELETE ON bfc_app_action_outbox
            FOR EACH ROW EXECUTE FUNCTION bfc_app_action_outbox_reject_mutation()
            SQL);
    }
};
