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
            // Empty string on the subject's own containment row; set on
            // the rows naming each bound user the offboard deactivated —
            // the guard rejects those users on every request thereafter.
            // NOT NULL deliberately: NULLs never collide under a unique
            // index, and the subject row's uniqueness is what makes two
            // racing first offboards idempotent instead of double-writing.
            $table->string('user_id')->default('');
            $table->timestamp('offboarded_at');
            $table->timestamps();

            $table->unique(['subject_type', 'subject_ref', 'user_id']);
            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('offboarded_subjects');
    }
};
