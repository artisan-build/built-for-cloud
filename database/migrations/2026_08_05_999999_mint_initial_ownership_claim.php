<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

return new class extends Migration
{
    public function up(): void
    {
        if (app()->runningUnitTests()) {
            return;
        }

        $claimed = DB::table('ownership')
            ->whereNotNull('owner_token_id')
            ->exists();

        if ($claimed || DB::table('ownership_claims')->whereNull('consumed_at')->exists()) {
            return;
        }

        $plainTextToken = bin2hex(random_bytes(32));
        $now = now();

        DB::table('ownership_claims')->insert([
            'id' => (string) Str::uuid(),
            'token_hash' => hash('sha256', $plainTextToken),
            'consumed_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        Log::info('Built for Cloud ownership claim token minted.', [
            'claim_token' => $plainTextToken,
        ]);
    }

    public function down(): void
    {
        // The one-time plaintext token is intentionally not recoverable.
    }
};
