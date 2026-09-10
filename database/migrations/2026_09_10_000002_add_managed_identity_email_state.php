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
            $table->string('normalized_email')
                ->storedAs('lower(email)')
                ->unique('users_normalized_email_unique');
            $table->timestamp('email_conflict_at')->nullable();
            $table->string('email_conflict_source')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropUnique('users_normalized_email_unique');
            $table->dropColumn([
                'normalized_email',
                'email_conflict_at',
                'email_conflict_source',
            ]);
        });
    }
};
