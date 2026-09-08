<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password')->nullable();
            $table->string('role', 16)->default(UserRole::Member->value);
            $table->string('status', 16)->default('active');
            $table->string('owner_slot', 16)->nullable()->unique();
            $table->string('scalpels_issuer')->nullable();
            $table->string('scalpels_connection_id')->nullable();
            $table->string('scalpels_id')->nullable();
            $table->string('original_contact_email')->nullable();
            $table->boolean('email_is_generated')->default(false);
            $table->timestamp('last_authenticated_at')->nullable();
            $table->timestamp('membership_confirmed_at')->nullable();
            $table->timestamp('membership_checked_at')->nullable();
            $table->timestamp('membership_response_at')->nullable();
            $table->timestamp('deactivated_at')->nullable();
            $table->rememberToken();
            $table->timestamps();

            $table->unique(
                ['scalpels_issuer', 'scalpels_connection_id', 'scalpels_id'],
                'users_scalpels_identity_unique',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
