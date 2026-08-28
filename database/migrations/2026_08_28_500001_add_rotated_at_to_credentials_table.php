<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The provenance marker rotation stamps on the unified store's outgoing
     * row (PRD 1.7, D6) — the same marker `api_tokens.rotated_at` carries:
     * "superseded by rotation", assertable only by the rotate verb. The
     * row's death still comes from `expires_at` (the grace window); this
     * column only records WHY that expiry exists.
     */
    public function up(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->timestamp('rotated_at')->nullable()->after('revoked_at');
        });
    }

    public function down(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->dropColumn('rotated_at');
        });
    }
};
