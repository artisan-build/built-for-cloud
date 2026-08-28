<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The rotation-provenance marker: only `TokenRegistry::rotate()` sets
     * it, meaning "this row was superseded by rotation". The claim-code
     * exchange sweep trusts it instead of guessing from expiry shapes.
     */
    public function up(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->timestamp('rotated_at')->nullable()->after('revoked_at');
        });
    }

    public function down(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->dropColumn('rotated_at');
        });
    }
};
