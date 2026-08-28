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
     * A deliberate NO-OP (FLT-F, PRD 1.13): the package refuses to drop a
     * table it cannot prove it created. up() records this migration as
     * run whether it created the table, was skipped by the flag, or was
     * skipped because the APP's own table pre-existed — so at rollback
     * time, flag-on + table-present does NOT distinguish the package's
     * table from the app's, and no flag or hasTable check can. Dropping
     * wrongly is unrecoverable data loss; not dropping costs an operator
     * one manual `DROP TABLE invitations` when they truly want the
     * package's table gone (release-notes/invitations-convergence.md).
     */
    public function down(): void
    {
        // Intentionally empty: rollback never drops the invitations table.
    }
};
