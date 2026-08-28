<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            // The hmac kind's signing key at rest: ENCRYPTED, never hashed
            // (D9.1) — both sides need the key, so a hash cannot sign.
            // NULL on every other kind, enforced by the model.
            $table->text('secret_ciphertext')->nullable();
            // Which encryption key produced the ciphertext (SEC-V3-08): a
            // content-addressed fingerprint of the APP_KEY that encrypted
            // it. Indexed because the staged rewrap selects and counts by
            // it ("verify zero old-version rows").
            $table->string('secret_key_version', 64)->nullable()->index();
            // Delivery provenance: when the signing key reached its
            // receiver (reveal-once at mint, or the claim exchange).
            // Activation refuses while this is NULL — an undelivered key
            // cannot have been installed.
            $table->timestamp('delivered_at')->nullable();
            // When the pending→active cutover happened (the hmac kind's
            // signing cutover, PRD 1.21 / SEC-V3-01).
            $table->timestamp('activated_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->dropColumn(['secret_ciphertext', 'secret_key_version', 'delivered_at', 'activated_at']);
        });
    }
};
