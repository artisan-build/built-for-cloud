<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * A claim code is optionally addressed (D1d): a hitch claim code is
     * addressed to nobody, so `email` becomes nullable.
     */
    public function up(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->string('email')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->string('email')->nullable(false)->change();
        });
    }
};
