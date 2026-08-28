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
            // Which delivery of an hmac key this row is on: 0 = never
            // delivered; each delivery or redelivery increments it. The
            // counter is what makes delivery fingerprints unambiguous
            // across redeliveries.
            $table->unsignedInteger('delivered_generation')->default(0);
            // The NON-RECOVERABLE fingerprint of the current delivery
            // (a hash over the delivered key material + the generation,
            // never the key): the activation verb requires it, so a stale
            // confirmation — one made before a redelivery re-keyed the row
            // — can never activate key material the confirmer never saw
            // (SEC-V3-01 rework, finding 1).
            $table->string('delivery_fingerprint', 64)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->dropColumn(['delivered_generation', 'delivery_fingerprint']);
        });
    }
};
