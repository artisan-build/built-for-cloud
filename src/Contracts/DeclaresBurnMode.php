<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\BurnMode;

/**
 * Opt-in extension of {@see CredentialDeclaration}: declare when this app's
 * claim codes burn. A declaration that does not implement this interface
 * gets {@see BurnMode::FirstUse} — the mode `api_tokens` providers honour —
 * so no existing declaration breaks and the default stays the contract's.
 */
interface DeclaresBurnMode
{
    public function burnMode(): BurnMode;
}
