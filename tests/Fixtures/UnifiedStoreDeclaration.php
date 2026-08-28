<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresDurableStore;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Http\Request;

/**
 * A declaration that targets the unified store for the claim exchange's
 * durable mint — the rebuild-time opt-in (PRD 1.0). Burn mode is NOT
 * declared, so the default `first_use` applies.
 */
final class UnifiedStoreDeclaration implements CredentialDeclaration, DeclaresDurableStore
{
    public function durableCredentialStore(): DurableStore
    {
        return DurableStore::Credentials;
    }

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }
}
