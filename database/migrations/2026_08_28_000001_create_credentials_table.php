<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('credentials', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('kind', 32);
            $table->string('subject_type', 32);
            $table->string('subject_ref');
            // Decorative label. Deliberately NON-unique: rotation depends on
            // duplicate names, and tenancy lives in subject_ref, never here.
            $table->string('name')->nullable()->index();
            $table->json('abilities')->nullable();
            // Stringified host-app user key; the package does not know the
            // host's user key type, so no FK.
            $table->string('user_id', 64)->nullable()->index();
            // sha256 hex digest for bearer/basic (and, later, hmac). Always
            // NULL for asymmetric rows, which carry a public key instead.
            $table->string('secret_hash', 64)->nullable()->unique();
            $table->text('public_key')->nullable();
            $table->string('status', 16)->default('active');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index(['subject_type', 'subject_ref']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('credentials');
    }
};
