<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password')->nullable();
            $table->string('role', 16)->default(UserRole::Member->value);
            $table->string('status', 16)->default('active');
            $table->string('owner_slot', 16)
                ->nullable()
                ->storedAs("CASE WHEN role = 'owner' THEN 'owner' ELSE NULL END")
                ->unique();
            $table->string('scalpels_issuer')->nullable();
            $table->string('scalpels_connection_id')->nullable();
            $table->string('scalpels_id')->nullable();
            $table->string('original_contact_email')->nullable();
            $table->boolean('email_is_generated')->default(false);
            $table->timestamp('last_authenticated_at')->nullable();
            $table->timestamp('membership_confirmed_at')->nullable();
            $table->timestamp('membership_checked_at')->nullable();
            $table->timestamp('membership_response_at')->nullable();
            $table->timestamp('deactivated_at')->nullable();
            $table->rememberToken();
            $table->timestamps();

            $table->unique(
                ['scalpels_issuer', 'scalpels_connection_id', 'scalpels_id'],
                'users_scalpels_identity_unique',
            );
        });

        match (Schema::getConnection()->getDriverName()) {
            'sqlite' => $this->guardSqliteExternalIdentity(),
            'mysql', 'mariadb' => $this->guardMysqlExternalIdentity(),
            'pgsql' => $this->guardPgsqlExternalIdentity(),
            default => null,
        };
    }

    public function down(): void
    {
        if (Schema::getConnection()->getDriverName() === 'pgsql' && Schema::hasTable('users')) {
            DB::statement('DROP TRIGGER IF EXISTS users_external_identity_complete ON users');
            DB::statement('DROP FUNCTION IF EXISTS users_reject_partial_external_identity()');
        }

        Schema::dropIfExists('users');
    }

    private function guardSqliteExternalIdentity(): void
    {
        foreach (['INSERT', 'UPDATE'] as $operation) {
            DB::unprepared(<<<SQL
                CREATE TRIGGER users_external_identity_complete_{$operation}
                BEFORE {$operation} ON users
                WHEN (NEW.scalpels_issuer IS NULL) + (NEW.scalpels_connection_id IS NULL) + (NEW.scalpels_id IS NULL) NOT IN (0, 3)
                BEGIN
                    SELECT RAISE(ABORT, 'Scalpels identity must be fully null or fully populated');
                END
                SQL);
        }
    }

    private function guardMysqlExternalIdentity(): void
    {
        foreach (['INSERT', 'UPDATE'] as $operation) {
            DB::unprepared(<<<SQL
                CREATE TRIGGER users_external_identity_complete_{$operation}
                BEFORE {$operation} ON users
                FOR EACH ROW
                BEGIN
                    IF ((NEW.scalpels_issuer IS NULL) + (NEW.scalpels_connection_id IS NULL) + (NEW.scalpels_id IS NULL)) NOT IN (0, 3) THEN
                        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Scalpels identity must be fully null or fully populated';
                    END IF;
                END
                SQL);
        }
    }

    private function guardPgsqlExternalIdentity(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION users_reject_partial_external_identity() RETURNS trigger AS $$
            BEGIN
                IF num_nulls(NEW.scalpels_issuer, NEW.scalpels_connection_id, NEW.scalpels_id) NOT IN (0, 3) THEN
                    RAISE EXCEPTION 'Scalpels identity must be fully null or fully populated';
                END IF;

                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            SQL);

        DB::unprepared(<<<'SQL'
            CREATE TRIGGER users_external_identity_complete
            BEFORE INSERT OR UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION users_reject_partial_external_identity()
            SQL);
    }
};
