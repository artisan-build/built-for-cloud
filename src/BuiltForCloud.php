<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final class BuiltForCloud
{
    public const VERSION = '0.7.0';

    /**
     * The public HTTP contract's major version (docs/http-contract.md, PRD
     * 0.2). Bumps whenever a DOCUMENTED request or response shape changes
     * incompatibly — a removal, rename, type change, or semantics change.
     * Additive fields never bump it; consumers must ignore unknown fields.
     *
     * 2 (this release): the credential listing grew its additive field set
     * (id, request_count, subject pair, status, cadence), revoke-by-name's
     * response became `200 {"revoked_ids": [...]}`, and the unified-store
     * verb routes exist. The contract doc's changelog carries the full
     * inventory — update BOTH when this changes, and never let this
     * constant stagnate while shapes move (it sat at 1 across 0.3.3→0.4.0
     * while the listing grew; that is the failure this rule exists to end).
     */
    public const API_VERSION = 2;
}
