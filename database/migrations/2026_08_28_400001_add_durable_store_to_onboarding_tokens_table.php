<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Which store a claim code's linked durable was minted into. NULL is
     * the backfill semantics: `api_tokens`, the only store that existed
     * before the seam toggle — so every pre-existing linkage keeps meaning
     * exactly what it meant. Exchange stamps the value it minted into; the
     * make-before-break revocation reads the RECORDED store, never the
     * current declaration, so a declaration switching stores can never
     * strand a still-live durable.
     */
    public function up(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->string('durable_store', 32)->nullable()->after('durable_token_id');
        });
    }

    public function down(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->dropColumn('durable_store');
        });
    }
};
