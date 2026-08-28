<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Database;

use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * The initial ownership-claim mint the install migration runs (D1c), as
 * an invokable so the migration stays a thin shell and this behaviour is
 * directly testable.
 *
 * THE D7 BUG FIX (PRD 1.14, its own commit, mutation-verified): this
 * step used to `Log::info` the PLAINTEXT claim token — the one-time,
 * admin-yielding secret — into the application log, where log shipping,
 * retention, and every reader with log access could copy it. The log
 * line now carries the claim row id and timestamp ONLY; the plaintext is
 * deliberately dropped on the floor (it was never recoverable later
 * anyway — only its hash is stored). The delivery path for an unclaimed
 * environment is `bfc:ownership:mint-claim` — TTY, shown once (D7's
 * reveal-once rule), built for exactly this.
 *
 * Flag-gated (PRD 1.14): the mint is a DATA migration, so it runs only
 * while the `data_migrations` surface family is on — an app can take the
 * package schema without the framework seeding claim state into it.
 * Idempotent besides: a claimed instance, or one already holding a
 * pending claim, mints nothing.
 */
final class MintInitialOwnershipClaim
{
    public function __construct(private readonly OwnershipClaimMinter $minter) {}

    public function __invoke(): void
    {
        if (! (bool) config('built-for-cloud.surfaces.data_migrations', true)) {
            return;
        }

        $claimed = DB::table('ownership')
            ->whereNotNull('owner_token_id')
            ->exists();

        if ($claimed || DB::table('ownership_claims')->whereNull('consumed_at')->exists()) {
            return;
        }

        [, $claim] = $this->minter->mint();

        // Bounded and secret-free: ids and timestamps only, NEVER the
        // token. The plaintext of this mint is unrecoverable by design;
        // the operator mints a deliverable one with the named command.
        Log::info('Built for Cloud minted the initial ownership claim. The claim token is not logged; run bfc:ownership:mint-claim to mint a deliverable claim token.', [
            'claim_id' => $claim->id,
            'minted_at' => now()->toIso8601String(),
        ]);
    }
}
