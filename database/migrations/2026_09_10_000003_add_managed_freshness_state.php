<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('managed_membership_status', 16)->nullable();
            $table->string('managed_membership_role', 16)->nullable();
            $table->unsignedBigInteger('managed_membership_generation')->nullable();
            $table->unsignedBigInteger('managed_membership_roster_version')->nullable();
            $table->unsignedBigInteger('managed_membership_response_sequence')->nullable();
            $table->string('managed_membership_responded_at', 64)->nullable();
        });

        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->string('managed_connection_status', 16)->nullable();
            $table->unsignedBigInteger('managed_connection_generation')->nullable();
            $table->unsignedBigInteger('managed_connection_roster_version')->nullable();
            $table->unsignedBigInteger('managed_connection_response_sequence')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('bfc_authority', function (Blueprint $table): void {
            $table->dropColumn([
                'managed_connection_status',
                'managed_connection_generation',
                'managed_connection_roster_version',
                'managed_connection_response_sequence',
            ]);
        });

        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn([
                'managed_membership_status',
                'managed_membership_role',
                'managed_membership_generation',
                'managed_membership_roster_version',
                'managed_membership_response_sequence',
                'managed_membership_responded_at',
            ]);
        });
    }
};
