<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->string('issuer')->nullable();
            $table->string('connection_id')->nullable();
            $table->string('organization_id')->nullable();
            $table->string('installation_id')->nullable();
            $table->string('authority_base_url', 2048)->nullable();
        });

        Schema::create('bfc_managed_handoffs', function (Blueprint $table): void {
            $table->string('state_hash', 64)->primary();
            $table->string('session_nonce_hash', 64);
            $table->string('issuer');
            $table->string('connection_id');
            $table->string('organization_id');
            $table->string('installation_id');
            $table->unsignedBigInteger('authority_generation');
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_managed_handoffs');

        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->dropColumn([
                'issuer',
                'connection_id',
                'organization_id',
                'installation_id',
                'authority_base_url',
            ]);
        });
    }
};
