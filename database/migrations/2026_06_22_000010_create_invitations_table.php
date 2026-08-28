<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false || Schema::hasTable('invitations')) {
            return;
        }

        Schema::create('invitations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->index();
            $table->string('token', 64)->unique();
            $table->uuid('invited_by')->nullable();
            $table->timestamp('accepted_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Guarded like up() (FLT-F): on an environment where the flag is off,
     * the package created nothing — this migration records as run having
     * skipped — and a `migrate:rollback` must not drop the APP's own
     * invitations table. The hasTable guard rides along per PRD 1.13; the
     * flag (Phase 0.5) is the data guard for a table the app created
     * before the flag was set.
     */
    public function down(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false || ! Schema::hasTable('invitations')) {
            return;
        }

        Schema::dropIfExists('invitations');
    }
};
