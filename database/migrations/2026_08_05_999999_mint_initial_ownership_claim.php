<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

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

        [$plainTextToken] = app(OwnershipClaimMinter::class)->mint();

        Log::info('Built for Cloud ownership claim token minted.', [
            'claim_token' => $plainTextToken,
        ]);
    }

    public function down(): void
    {
        // The one-time plaintext token is intentionally not recoverable.
    }
};
