<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Database\MintInitialOwnershipClaim;
use Illuminate\Database\Migrations\Migration;

return new class extends Migration
{
    public function up(): void
    {
        if (app()->runningUnitTests()) {
            return;
        }

        // The whole behaviour — the data_migrations surface flag, the
        // idempotence checks, and the D7-fixed secret-free logging —
        // lives in the invokable so it is directly testable.
        app(MintInitialOwnershipClaim::class)();
    }

    public function down(): void
    {
        // The one-time plaintext token is intentionally not recoverable.
    }
};
