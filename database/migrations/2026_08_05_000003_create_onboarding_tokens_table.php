<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('onboarding_tokens', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->index();
            $table->string('scope')->default(Scope::Consume->value);
            $table->string('token_hash', 64)->unique();
            $table->foreignUuid('durable_token_id')->nullable()->constrained('api_tokens')->nullOnDelete();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('onboarding_tokens');
    }
};
