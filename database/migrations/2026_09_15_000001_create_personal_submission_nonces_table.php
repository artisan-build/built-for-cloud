<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_personal_submission_nonces', function (Blueprint $table): void {
            $table->char('nonce_hash', 64)->primary();
            $table->char('session_hash', 64)->index();
            $table->string('user_id')->index();
            $table->string('verb', 16);
            $table->string('target');
            $table->timestamp('expires_at')->index();
            $table->timestamp('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_personal_submission_nonces');
    }
};
