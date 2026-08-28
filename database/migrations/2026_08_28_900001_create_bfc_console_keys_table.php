<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_console_keys', function (Blueprint $table): void {
            $table->uuid('id')->primary();

            // The `kid` the assertion's footer names. Unique: a key id
            // selects EXACTLY ONE verification key, so no two rows can
            // ever compete to verify the same token.
            $table->string('key_id', 64)->unique();

            // The PUBLIC half only, lower-case hex, 32 bytes = 64 chars.
            // The column is 64 wide so a 64-byte expanded Ed25519 secret
            // key (128 hex chars) cannot fit; note a 32-byte SEED is the
            // same size as a public key and would, so the width is a
            // guard against one shape of mistake, not a custody control.
            // Custody comes from the vendor holding every private half
            // and this package having no code that signs — which is why
            // stealing this entire database compromises no deployment's
            // signing authority (Console PRD D12).
            $table->string('public_key', 64);

            // Make-before-break rotation, as two SEPARATE steps: a key
            // arrives pending (`activated_at` null), is activated on its
            // own, and is retired later on its own. Two keys are active
            // at once for the whole overlap, which is what lets the
            // vendor re-key a live deployment without a flag day.
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('retired_at')->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_console_keys');
    }
};
