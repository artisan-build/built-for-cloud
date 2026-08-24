<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_client_identity_observations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            // The verbatim identity, for output only. NOT the key: it inherits the consuming
            // app's collation, and a case-insensitive one (MySQL's utf8mb4_0900_ai_ci default
            // among them) would collapse two byte-distinct identities into one row.
            $table->string('client_identity');
            // The key: lowercase sha256 hex of the exact bytes. Hex is ASCII, so a
            // case-insensitive collation on it is harmless, and it is exact on every driver.
            $table->string('client_identity_hash', 64)->unique();
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->unsignedInteger('observation_count')->default(0);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_client_identity_observations');
    }
};
