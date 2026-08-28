<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

/**
 * Optional companion to {@see CredentialDeclaration} (the DeclaresBurnMode
 * pattern): how "holder" resolves for a credential this app issued —
 * PRD 1.16's one lifecycle-notification policy.
 *
 * Return the bound user's email where the credential belongs to a person,
 * or null for NOBODY: an unbound subject (a CI key, an app token) notifies
 * no one. There is deliberately no operator fallback — a declaration that
 * cannot name a holder must not spam whoever configured the mail driver.
 */
interface DeclaresHolderResolution
{
    public function resolveHolderEmail(string $credentialId): ?string;
}
