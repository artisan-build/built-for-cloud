<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The D2 subject on the legacy `api_tokens` store: what one revocation
     * costs (`subject_type`) and which partition it costs it to
     * (`subject_ref` — tenancy lives here, never in the name).
     *
     * Both columns are NULLABLE, deliberately (declare-don't-guess): rows
     * minted before subjects existed carry null, meaning exactly "this POC
     * row predates subjects" — never a guessed classification. Neither
     * column ever grants anything; authority is the declaration's per-verb
     * matrix (PRD 1.4), to which a subject is only an input.
     */
    public function up(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->string('subject_type')->nullable()->after('abilities');
            $table->string('subject_ref')->nullable()->after('subject_type');
        });
    }

    public function down(): void
    {
        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->dropColumn(['subject_type', 'subject_ref']);
        });
    }
};
