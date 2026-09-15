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
        Schema::create('bfc_hmac_writer_barriers', function (Blueprint $table): void {
            $table->string('name')->primary();
        });

        DB::table('bfc_hmac_writer_barriers')->insert(['name' => 'rewrap']);
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_hmac_writer_barriers');
    }
};
