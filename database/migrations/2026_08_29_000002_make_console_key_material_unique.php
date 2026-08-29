<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * One key, one row — for the MATERIAL as well as the key id (Console PRD
 * D12, rework B4).
 *
 * The table shipped unique on `key_id` alone, which left retirement
 * defeatable: `k1` holding public key P, retired after its overlap,
 * could be re-filed as `{key_id: "k2", public_key: P}` and would verify
 * again. Retirement is the ONLY revocation this design has — there is no
 * CRL, no expiry on a console key, and no way to reach back into
 * assertions already minted — so a retirement that a later delivery can
 * undo is not a revocation at all.
 *
 * The constraint is the enforcement; {@see
 * \ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey} pre-checks so the
 * ordinary answer is a clean refusal rather than an integrity violation
 * surfacing as a 500. It covers every lifecycle state deliberately:
 * pending, active and RETIRED material alike is already-filed material.
 *
 * Scope, stated honestly: this is per DEPLOYMENT (per database). It says
 * nothing about the same key being filed at another deployment, which is
 * D12's business — a per-deployment audience is what makes that harmless.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('bfc_console_keys', function (Blueprint $table): void {
            $table->unique('public_key');
        });
    }

    public function down(): void
    {
        Schema::table('bfc_console_keys', function (Blueprint $table): void {
            $table->dropUnique(['public_key']);
        });
    }
};
