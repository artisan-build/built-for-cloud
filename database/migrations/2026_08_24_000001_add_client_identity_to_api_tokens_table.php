<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->string('client_identity')->nullable()->after('abilities');
            $table->timestamp('client_identity_last_seen_at')->nullable()->after('client_identity');
        });
    }

    public function down(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->dropColumn(['client_identity', 'client_identity_last_seen_at']);
        });
    }
};
