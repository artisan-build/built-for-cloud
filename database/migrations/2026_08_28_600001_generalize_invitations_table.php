<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The invitations convergence (PRD 1.13, D4): generalize the table IN
 * PLACE — no rename. Additive: `used_by` (who accepted, nullable
 * string(64)), `role` (stored, never interpreted), `email` nullable (open
 * codes are unaddressed), and `invited_by` widened from uuid to the
 * decided nullable string(64) shape so bigint and uuid inviter ids alike
 * stringify into it.
 *
 * ONE upgrade path for fresh and existing databases: the create migration
 * keeps its original shape and this migration always runs after it, so a
 * fresh database and a live 0.4.x database converge through identical
 * steps (the D4 fresh-database-divergence rule, applied inside the
 * package). Guarded on the package's own shape: an app-owned invitations
 * table (flag off, or no `token` column) is never touched.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false
            || ! Schema::hasTable('invitations')
            || ! Schema::hasColumn('invitations', 'token')) {
            return;
        }

        Schema::table('invitations', function (Blueprint $table): void {
            if (! Schema::hasColumn('invitations', 'used_by')) {
                $table->string('used_by', 64)->nullable();
            }

            if (! Schema::hasColumn('invitations', 'role')) {
                $table->string('role')->nullable();
            }
        });

        Schema::table('invitations', function (Blueprint $table): void {
            $table->string('email')->nullable()->change();
            $table->string('invited_by', 64)->nullable()->change();
        });
    }

    public function down(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false
            || ! Schema::hasTable('invitations')
            || ! Schema::hasColumn('invitations', 'token')) {
            return;
        }

        // Only the added columns are removed. Email nullability and the
        // invited_by widening are NOT reverted: rows written since may
        // carry nulls or 64-character refs, and a narrowing rollback would
        // destroy data.
        Schema::table('invitations', function (Blueprint $table): void {
            foreach (['used_by', 'role'] as $column) {
                if (Schema::hasColumn('invitations', $column)) {
                    $table->dropColumn($column);
                }
            }
        });
    }
};
