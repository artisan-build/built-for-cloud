<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Singleton custody row for the managed-auth client secret delivered
     * over the P1 enrolment/rotation calls. The row exists only while a
     * persisted secret does (enrolment creates it, disconnect deletes
     * it): ciphertext, the content-addressed APP_KEY version that
     * produced it, the domain-separated retry digest, and the secret's
     * OWN monotonic generation counter — rotation never touches the
     * authority generation.
     */
    public function up(): void
    {
        Schema::create('bfc_managed_client_secrets', function (Blueprint $table): void {
            $table->string('key', 32)->primary();
            $table->unsignedBigInteger('client_secret_generation');
            $table->text('secret_ciphertext');
            $table->string('secret_key_version', 16);
            $table->char('secret_retry_digest', 64);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_managed_client_secrets');
    }
};
