<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * Where the claim exchange's durable mint lands (PRD 1.0, the seam
 * toggle). `api_tokens` stays the default — the legacy onboarding flow's
 * consumers were built on it — and an app opts into the unified store at
 * rebuild time by declaring it ({@see Contracts\DeclaresDurableStore}).
 */
enum DurableStore: string
{
    case ApiTokens = 'api_tokens';
    case Credentials = 'credentials';
}
