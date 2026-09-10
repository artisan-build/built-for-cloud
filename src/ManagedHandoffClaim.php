<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use DateTimeInterface;
use Illuminate\Support\Facades\DB;

final class ManagedHandoffClaim
{
    public function consume(
        ManagedAuthConnection $connection,
        string $state,
        string $sessionNonce,
        DateTimeInterface $now,
        ?string $databaseConnection = null,
    ): bool {
        return DB::connection($databaseConnection)
            ->table('bfc_managed_handoffs')
            ->where('state_hash', hash('sha256', $state))
            ->where('session_nonce_hash', hash('sha256', $sessionNonce))
            ->where('issuer', $connection->issuer)
            ->where('connection_id', $connection->connectionId)
            ->where('organization_id', $connection->organizationId)
            ->where('installation_id', $connection->installationId)
            ->where('authority_generation', $connection->authorityGeneration)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $now)
            ->update([
                'consumed_at' => $now,
                'updated_at' => $now,
            ]) === 1;
    }
}
