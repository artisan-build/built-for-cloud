<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('offboarded_subjects', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('subject_type');
            $table->string('subject_ref');
            // Null on the subject's own containment row; set on the rows
            // naming each bound user the offboard deactivated — the guard
            // rejects those users on every request thereafter.
            $table->string('user_id')->nullable();
            $table->timestamp('offboarded_at');
            $table->timestamps();

            $table->index(['subject_type', 'subject_ref']);
            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('offboarded_subjects');
    }
};
