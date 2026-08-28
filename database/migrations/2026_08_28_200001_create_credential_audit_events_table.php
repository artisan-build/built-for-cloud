<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The instance-side, append-only audit model (PRD 1.9 / D8): the migration
 * ships in the framework, the rows live in each consuming app's own
 * database. Ids only — never secret values, never hashes.
 *
 * Append-only is enforced twice: the model throws on update/delete, and —
 * where the driver permits — database triggers abort UPDATE and DELETE so
 * raw query-builder writes cannot mutate history either.
 *
 * Honest limits of the database layer: on sqlite the triggers abort
 * ordinary UPDATE/DELETE statements, but anyone with schema access can
 * DROP the trigger (or use `PRAGMA writable_schema`), and direct file
 * access rewrites anything; mysql and pgsql triggers are likewise
 * droppable by a privileged connection. That is D8's stated trade: a
 * compromised instance can tamper with its own history — append-only is
 * by construction, not cryptographic. Drivers this migration does not
 * know (sqlsrv) get model-level enforcement only.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('credential_audit_events', function (Blueprint $table): void {
            $table->uuid('id')->primary();

            // The one event vocabulary (LifecycleEventType).
            $table->string('event', 32)->index();

            // Ids only, nullable each: a code event may precede any
            // credential; a credential event may involve no code.
            $table->uuid('code_id')->nullable()->index();
            $table->uuid('credential_id')->nullable()->index();

            // Supersession lineage, old -> new: on an event about a
            // superseded credential, the credential that replaced it. This
            // is what makes rotation auditable.
            $table->uuid('superseded_by_credential_id')->nullable();

            // Which instance, where known.
            $table->string('provider')->nullable();
            $table->string('deployment')->nullable();
            $table->string('environment')->nullable();

            // The actor model: type + ref strings covering D8's four
            // principals. No user PII beyond ids/refs.
            $table->string('actor_type', 32)->nullable();
            $table->string('actor_ref')->nullable();

            // The intended recipient, where the code was addressed at all.
            $table->string('recipient')->nullable();

            // TTL selected: the code lifetime, and the durable expiry where
            // the issuer chose one (never a default).
            $table->unsignedInteger('code_ttl_seconds')->nullable();
            $table->timestamp('credential_expires_at')->nullable();

            // Bounded reason enum + bounded free-text note. The note is
            // customer-visible: stored verbatim, escaped per renderer,
            // CSV-formula-neutralized on export (CsvFieldSanitizer).
            $table->string('reason_code', 32)->nullable();
            $table->string('note', 500)->nullable();

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
        if (Schema::getConnection()->getDriverName() === 'pgsql' && Schema::hasTable('credential_audit_events')) {
            DB::statement('DROP TRIGGER IF EXISTS credential_audit_events_append_only ON credential_audit_events');
            DB::statement('DROP FUNCTION IF EXISTS credential_audit_events_reject_mutation()');
        }

        // sqlite and mysql triggers drop with the table.
        Schema::dropIfExists('credential_audit_events');
    }

    private function guardSqlite(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER credential_audit_events_no_update
            BEFORE UPDATE ON credential_audit_events
            BEGIN
                SELECT RAISE(ABORT, 'credential_audit_events is append-only');
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER credential_audit_events_no_delete
            BEFORE DELETE ON credential_audit_events
            BEGIN
                SELECT RAISE(ABORT, 'credential_audit_events is append-only');
            END
            SQL);
    }

    private function guardMysql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER credential_audit_events_no_update
            BEFORE UPDATE ON credential_audit_events
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'credential_audit_events is append-only'
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER credential_audit_events_no_delete
            BEFORE DELETE ON credential_audit_events
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'credential_audit_events is append-only'
            SQL);
    }

    private function guardPgsql(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION credential_audit_events_reject_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'credential_audit_events is append-only';
            END;
            $$ LANGUAGE plpgsql
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER credential_audit_events_append_only
            BEFORE UPDATE OR DELETE ON credential_audit_events
            FOR EACH ROW EXECUTE FUNCTION credential_audit_events_reject_mutation()
            SQL);
    }
};
