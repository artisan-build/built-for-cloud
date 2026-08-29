<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The instance-side, append-only APP-ACTION audit stream (Console PRD
 * D17). A NEW table beside `credential_audit_events`, which is
 * credential-work only and is deliberately not extended: the rows live
 * in each consuming app's own database, and this migration ships in the
 * package.
 *
 * WHAT THE SCHEMA DECIDES, AND WHAT IT DOES NOT. The schema designates
 * no column for arbitrary app content or notes (D15) — no `note`,
 * nothing of that kind — and THAT absence is structural. It is not the
 * same as prose being impossible: several of the VARCHAR columns below
 * can physically hold it through the direct-write residue the model's
 * docblock names, and `on_behalf_of` intentionally IS display text. What
 * each
 * column CONTAINS is a different question, and the answer is a property
 * of `AppActionRecorder`, not of the table: on that path `action` is the
 * backing value of a case from a compile-time enum the app declares,
 * `action_vocabulary` is that enum's class name (so two apps' identical
 * slugs stay distinguishable), and `reason` is a closed package enum.
 *
 * The one string that is not an identifier is `on_behalf_of` — the
 * agency a delegated operator acts for, which D4 requires. On the
 * package's paths it is an issuer-minted claim the assertion verifier
 * bounded to 120 characters and rejected for control characters. **It is
 * caller-supplied, not verifier-guarded**: an earlier revision of this
 * sentence said it reached the column "from a verified assertion and
 * from nowhere else", which was false — a consuming app writing its own
 * rows, or calling the actor factory with its own string, puts whatever
 * it likes here. Escape it at every sink.
 *
 * Append-only has three tripwires — model events on update and delete,
 * an enumerated refusal list on the models' Eloquent builder, and, where
 * the driver permits, database triggers aborting raw row-level UPDATE
 * and DELETE. **None of them is a boundary**; the model's docblock says
 * what each one misses.
 *
 * Honest limits of the database layer, the same ones the credential
 * stream's migration states: on sqlite the triggers abort ordinary
 * UPDATE/DELETE, but anyone with schema access can DROP the trigger (or
 * use `PRAGMA writable_schema`), and direct file access rewrites
 * anything; mysql and pgsql triggers are likewise droppable by a
 * privileged connection. TRUNCATE is DDL and no row trigger sees it at
 * all, and no trigger here guards INSERT. Drivers this migration does
 * not know (sqlsrv) get model-level enforcement only. That is the stated
 * trade: an app, or a compromised instance, can tamper with its own
 * history — append-only here is a strong convention with tripwires under
 * it, not a cryptographic property.
 *
 * RETENTION: nothing in this package ever deletes a row here, and
 * storage is therefore unbounded. App-action events are attribution
 * history, the same decision already taken for the shadow-actor row. An
 * app deleting its own rows is outside what the package can see.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_app_action_events', function (Blueprint $table): void {
            // The stable event id D17 requires. `HasUuids` generates it
            // and the model does not make it fillable, so no create()
            // through the model can supply one; a raw insert can, like
            // any raw insert into an app's own table.
            $table->uuid('id')->primary();

            // The app's own compile-time vocabulary: the case's backing
            // value, and the enum class it came from. 64 is
            // MetadataShape::TOKEN's own bound, which the recorder holds
            // its own emissions to.
            $table->string('action', 64)->index();
            $table->string('action_vocabulary', 255);

            // The closed package reason vocabulary (AppActionReason).
            $table->string('reason', 32)->index();

            // The three principals D17 names (AppActorType), and the
            // identifier of the one that acted. On the recorder's path a
            // delegated actor's ref is the TYPE-QUALIFIED
            // `bfc-console:{id}` form, taken from the actor model
            // itself: the actor table is an ordinary auto-increment in
            // the same id space `users` occupies, so a bare `7` would
            // read as user 7.
            $table->string('actor_type', 32)->index();
            $table->string('actor_ref', 255);

            // D4's agency. On the recorder's path only a delegated
            // actor can carry one, and the model's `creating` hook
            // refuses the other combinations on the writes that fire it.
            // The COLUMN constrains nothing — a raw insert can pair it
            // with any actor type. The width is the assertion verifier's
            // own bound for the claim it comes from.
            $table->string('on_behalf_of', 120)->nullable();

            $table->timestamp('occurred_at')->index();
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
        if (Schema::getConnection()->getDriverName() === 'pgsql' && Schema::hasTable('bfc_app_action_events')) {
            DB::statement('DROP TRIGGER IF EXISTS bfc_app_action_events_append_only ON bfc_app_action_events');
            DB::statement('DROP FUNCTION IF EXISTS bfc_app_action_events_reject_mutation()');
        }

        // sqlite and mysql triggers drop with the table.
        Schema::dropIfExists('bfc_app_action_events');
    }

    private function guardSqlite(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_events_no_update
            BEFORE UPDATE ON bfc_app_action_events
            BEGIN
                SELECT RAISE(ABORT, 'bfc_app_action_events is append-only');
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_events_no_delete
            BEFORE DELETE ON bfc_app_action_events
            BEGIN
                SELECT RAISE(ABORT, 'bfc_app_action_events is append-only');
            END
            SQL);
    }

    private function guardMysql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_events_no_update
            BEFORE UPDATE ON bfc_app_action_events
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bfc_app_action_events is append-only'
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_events_no_delete
            BEFORE DELETE ON bfc_app_action_events
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bfc_app_action_events is append-only'
            SQL);
    }

    private function guardPgsql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION bfc_app_action_events_reject_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'bfc_app_action_events is append-only';
            END;
            $$ LANGUAGE plpgsql
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_app_action_events_append_only
            BEFORE UPDATE OR DELETE ON bfc_app_action_events
            FOR EACH ROW EXECUTE FUNCTION bfc_app_action_events_reject_mutation()
            SQL);
    }
};
