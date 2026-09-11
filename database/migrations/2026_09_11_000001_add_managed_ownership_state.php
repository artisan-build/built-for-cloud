<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->unsignedBigInteger('managed_ownership_generation')->nullable();
            $table->unsignedBigInteger('managed_ownership_roster_version')->nullable();
            $table->unsignedBigInteger('managed_ownership_response_sequence')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->dropColumn([
                'managed_ownership_generation',
                'managed_ownership_roster_version',
                'managed_ownership_response_sequence',
            ]);
        });
    }
};
