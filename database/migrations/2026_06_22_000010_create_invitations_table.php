<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('invitations', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->nullable()->index();
            $table->string('token', 64)->unique();
            $table->string('invited_by', 64)->nullable();
            $table->string('used_by', 64)->nullable();
            $table->string('role', 16)->nullable();
            $table->timestamp('accepted_at')->nullable();
            $table->timestamp('cancelled_at')->nullable();
            $table->timestamp('expires_at');
            $table->string('pending_email')->nullable()
                ->storedAs('CASE WHEN accepted_at IS NULL AND cancelled_at IS NULL THEN lower(email) ELSE NULL END')
                ->unique();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('invitations');
    }
};
