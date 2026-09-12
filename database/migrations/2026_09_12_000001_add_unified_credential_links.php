<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // The historical filename predates P5c; these are now the sole links
        // to credentials, not additions beside legacy token columns.
        Schema::table('ownership', function (Blueprint $table): void {
            $table->foreignUuid('owner_credential_id')->nullable()->constrained('credentials')->nullOnDelete();
        });

        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->foreignUuid('durable_credential_id')->nullable()->constrained('credentials')->nullOnDelete();
        });

        Schema::table('credentials', function (Blueprint $table): void {
            $table->string('client_identity')->nullable();
            $table->timestamp('client_identity_last_seen_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->dropColumn(['client_identity', 'client_identity_last_seen_at']);
        });

        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('durable_credential_id');
        });

        Schema::table('ownership', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('owner_credential_id');
        });
    }
};
