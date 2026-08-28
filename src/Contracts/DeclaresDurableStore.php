<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\DurableStore;

/**
 * Opt-in extension of {@see CredentialDeclaration} — which store the claim
 * exchange's durable mint targets through the {@see DurableCredentialMinter}
 * seam (PRD 1.0). Not implementing it keeps today's behaviour exactly:
 * exchange mints into `api_tokens`. An app declares
 * {@see DurableStore::Credentials} at rebuild time to have exchange mint a
 * unified-store row instead — burn semantics (first-use or at-exchange, per
 * the declared mode) and make-before-break both follow the declared store.
 */
interface DeclaresDurableStore
{
    public function durableCredentialStore(): DurableStore;
}
