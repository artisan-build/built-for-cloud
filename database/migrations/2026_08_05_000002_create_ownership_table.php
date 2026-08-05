<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ownership', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('owner_token_id')->nullable()->constrained('api_tokens')->nullOnDelete();
            $table->string('notify_callback')->nullable();
            $table->string('webhook_secret')->nullable();
            $table->foreignUuid('pending_claim_id')->nullable()->constrained('ownership_claims')->nullOnDelete();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ownership');
    }
};
