<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_authority', function (Blueprint $table): void {
            $table->string('key', 32)->primary();
            $table->string('mode', 16);
            $table->unsignedBigInteger('generation');
            $table->timestamps();
        });

        DB::table('bfc_authority')->insert([
            'key' => InstallationAuthority::KEY,
            'mode' => AuthorityMode::Standalone->value,
            'generation' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_authority');
    }
};
