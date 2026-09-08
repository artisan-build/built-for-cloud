<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_authority', function (Blueprint $table): void {
            $table->string('key', 32)->primary();
            $table->string('mode', 16);
            $table->unsignedBigInteger('generation');
            $table->timestamps();
        });

        match (Schema::getConnection()->getDriverName()) {
            'sqlite' => $this->guardSqliteAuthority(),
            'mysql', 'mariadb' => $this->guardMysqlAuthority(),
            'pgsql' => $this->guardPgsqlAuthority(),
            default => null,
        };

        DB::table('bfc_authority')->insert([
            'key' => InstallationAuthority::KEY,
            'mode' => AuthorityMode::Standalone->value,
            'generation' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function down(): void
    {
        if (Schema::getConnection()->getDriverName() === 'pgsql' && Schema::hasTable('bfc_authority')) {
            DB::statement('DROP TRIGGER IF EXISTS bfc_authority_validate ON bfc_authority');
            DB::statement('DROP FUNCTION IF EXISTS bfc_authority_reject_invalid_mutation()');
        }

        Schema::dropIfExists('bfc_authority');
    }

    private function guardSqliteAuthority(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_validate_insert
            BEFORE INSERT ON bfc_authority
            WHEN EXISTS (SELECT 1 FROM bfc_authority WHERE key = 'installation')
                OR NEW.key IS NOT 'installation'
                OR NEW.mode NOT IN ('standalone', 'managed')
                OR typeof(NEW.generation) IS NOT 'integer'
                OR NEW.generation < 1
            BEGIN
                SELECT RAISE(ABORT, 'Invalid installation authority');
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_validate_update
            BEFORE UPDATE ON bfc_authority
            WHEN NEW.key IS NOT 'installation'
                OR NEW.mode NOT IN ('standalone', 'managed')
                OR typeof(NEW.generation) IS NOT 'integer'
                OR NEW.generation < OLD.generation
                OR (NEW.mode IS NOT OLD.mode AND NEW.generation <= OLD.generation)
            BEGIN
                SELECT RAISE(ABORT, 'Invalid installation authority change');
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_reject_delete
            BEFORE DELETE ON bfc_authority
            BEGIN
                SELECT RAISE(ABORT, 'The installation authority record cannot be deleted');
            END
            SQL);
    }

    private function guardMysqlAuthority(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_validate_insert
            BEFORE INSERT ON bfc_authority
            FOR EACH ROW
            BEGIN
                IF NEW.key <> 'installation' OR NEW.mode NOT IN ('standalone', 'managed') OR NEW.generation < 1 THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid installation authority';
                END IF;
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_validate_update
            BEFORE UPDATE ON bfc_authority
            FOR EACH ROW
            BEGIN
                IF NEW.key <> 'installation'
                    OR NEW.mode NOT IN ('standalone', 'managed')
                    OR NEW.generation < OLD.generation
                    OR (NEW.mode <> OLD.mode AND NEW.generation <= OLD.generation) THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid installation authority change';
                END IF;
            END
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_reject_delete
            BEFORE DELETE ON bfc_authority
            FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'The installation authority record cannot be deleted'
            SQL);
    }

    private function guardPgsqlAuthority(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION bfc_authority_reject_invalid_mutation() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'The installation authority record cannot be deleted';
                END IF;

                IF NEW.key <> 'installation'
                    OR NEW.mode NOT IN ('standalone', 'managed')
                    OR NEW.generation < 1 THEN
                    RAISE EXCEPTION 'Invalid installation authority';
                END IF;

                IF TG_OP = 'UPDATE' AND (
                    NEW.generation < OLD.generation
                    OR (NEW.mode <> OLD.mode AND NEW.generation <= OLD.generation)
                ) THEN
                    RAISE EXCEPTION 'Invalid installation authority change';
                END IF;

                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER bfc_authority_validate
            BEFORE INSERT OR UPDATE OR DELETE ON bfc_authority
            FOR EACH ROW EXECUTE FUNCTION bfc_authority_reject_invalid_mutation()
            SQL);
    }
};
