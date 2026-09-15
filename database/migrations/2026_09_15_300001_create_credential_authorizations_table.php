<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('credential_authorizations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('flow', 16);
            $table->char('device_code_hash', 64)->nullable()->unique();
            $table->char('user_code_hash', 64)->nullable()->unique();
            $table->text('redirect_uri')->nullable();
            $table->char('pkce_challenge', 43)->nullable();
            $table->char('authorization_code_hash', 64)->nullable()->unique();
            $table->string('status', 16);
            $table->string('denial_reason', 32)->nullable();
            $table->string('app_purpose');
            $table->string('protocol_purpose', 32);
            $table->string('subject_type', 32);
            $table->string('subject_ref');
            $table->string('installation_ref');
            $table->string('application_ref');
            $table->string('audience');
            $table->string('ownership', 16);
            $table->json('abilities');
            $table->string('label', 64)->nullable();
            $table->timestamp('credential_expires_at')->nullable();
            $table->string('initiating_user_id', 64)->index();
            $table->char('browser_session_nonce_hash', 64);
            $table->unsignedSmallInteger('base_interval')->nullable();
            $table->unsignedSmallInteger('effective_interval')->nullable();
            $table->timestamp('last_polled_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('decided_at')->nullable();
            $table->timestamp('consumed_at')->nullable();
            $table->uuid('issued_credential_id')->nullable()->index();
            $table->timestamps();

            $table->index(['subject_type', 'subject_ref', 'ownership'], 'credential_authorizations_subject');
            $table->index(['ownership', 'initiating_user_id', 'status'], 'credential_authorizations_user');
            $table->index(['installation_ref', 'ownership', 'status'], 'credential_authorizations_installation');
        });

        Schema::table('credential_audit_events', function (Blueprint $table): void {
            $table->string('event', 64)->change();
            $table->uuid('credential_authorization_id')->nullable()->index()->after('credential_id');
        });

        $this->addShapeConstraints();
    }

    public function down(): void
    {
        Schema::table('credential_audit_events', function (Blueprint $table): void {
            $table->dropIndex(['credential_authorization_id']);
            $table->dropColumn('credential_authorization_id');
            $table->string('event', 32)->change();
        });

        Schema::dropIfExists('credential_authorizations');
    }

    private function addShapeConstraints(): void
    {
        $shape = <<<'SQL'
            ((flow = 'device'
                AND device_code_hash IS NOT NULL
                AND user_code_hash IS NOT NULL
                AND redirect_uri IS NULL
                AND pkce_challenge IS NULL
                AND authorization_code_hash IS NULL
                AND base_interval BETWEEN 5 AND 30
                AND effective_interval BETWEEN 5 AND 30)
            OR
            (flow = 'loopback'
                AND device_code_hash IS NULL
                AND user_code_hash IS NULL
                AND redirect_uri IS NOT NULL
                AND pkce_challenge IS NOT NULL
                AND base_interval IS NULL
                AND effective_interval IS NULL
                AND last_polled_at IS NULL
                AND ((status = 'pending' AND authorization_code_hash IS NULL)
                    OR (status IN ('approved', 'consumed') AND authorization_code_hash IS NOT NULL)
                    OR status = 'denied')))
            AND status IN ('pending', 'approved', 'denied', 'consumed')
            AND ((status = 'denied' AND denial_reason IS NOT NULL) OR (status <> 'denied' AND denial_reason IS NULL))
            AND ((status = 'consumed' AND consumed_at IS NOT NULL AND issued_credential_id IS NOT NULL)
                OR (status <> 'consumed' AND consumed_at IS NULL AND issued_credential_id IS NULL))
            SQL;

        $driver = Schema::getConnection()->getDriverName();

        if (in_array($driver, ['pgsql', 'mysql', 'mariadb'], true)) {
            DB::statement('ALTER TABLE credential_authorizations ADD CONSTRAINT credential_authorizations_shape CHECK ('.$shape.')');

            return;
        }

        if ($driver === 'sqlite') {
            $columns = [
                'flow', 'device_code_hash', 'user_code_hash', 'redirect_uri', 'pkce_challenge',
                'authorization_code_hash', 'base_interval', 'effective_interval', 'last_polled_at',
                'status', 'denial_reason', 'consumed_at', 'issued_credential_id',
            ];
            $sqliteShape = preg_replace(
                '/\\b('.implode('|', $columns).')\\b/',
                'NEW.$1',
                $shape,
            );
            DB::unprepared('CREATE TRIGGER credential_authorizations_shape_insert BEFORE INSERT ON credential_authorizations WHEN NOT ('.$sqliteShape.") BEGIN SELECT RAISE(ABORT, 'invalid credential authorization shape'); END");
            DB::unprepared('CREATE TRIGGER credential_authorizations_shape_update BEFORE UPDATE ON credential_authorizations WHEN NOT ('.$sqliteShape.") BEGIN SELECT RAISE(ABORT, 'invalid credential authorization shape'); END");
        }
    }
};
