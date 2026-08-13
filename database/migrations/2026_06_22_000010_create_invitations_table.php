<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false || Schema::hasTable('invitations')) {
            return;
        }

        Schema::create('invitations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->index();
            $table->string('token', 64)->unique();
            $table->uuid('invited_by')->nullable();
            $table->timestamp('accepted_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        if (config('built-for-cloud.auth_foundation.invitations') === false) {
            return;
        }

        Schema::dropIfExists('invitations');
    }
};
