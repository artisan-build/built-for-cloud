<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->string('purpose', 32)->nullable();
        });

        $retiredAt = now();

        DB::table('credentials')
            ->whereNull('revoked_at')
            ->update(['revoked_at' => $retiredAt]);
    }

    public function down(): void
    {
        Schema::table('credentials', function (Blueprint $table): void {
            $table->dropColumn('purpose');
        });
    }
};
