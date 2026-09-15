<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresSelfServiceMintPolicy;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;

/**
 * Resolves the host's one self-service kind policy for every surface that
 * lets an authenticated human mint or rotate credentials.
 */
final readonly class SelfServiceKindPolicyResolver
{
    /** @var list<CredentialKind> */
    private const array DEFAULT_PERSONAL_KINDS = [CredentialKind::Bearer];

    public function __construct(private CredentialDeclaration $declaration) {}

    /** @return list<CredentialKind> */
    public function personalKinds(Subject $subject): array
    {
        return $this->kinds($subject, self::DEFAULT_PERSONAL_KINDS);
    }

    /** @return list<CredentialKind> */
    public function installationKinds(Subject $subject): array
    {
        return $this->kinds($subject, CredentialKind::cases());
    }

    /** @throws CredentialVerbRefused */
    public function assertPersonalKindAllowed(Subject $subject, CredentialKind $kind): void
    {
        $this->assertAllowed($kind, $this->personalKinds($subject));
    }

    /** @throws CredentialVerbRefused */
    public function assertInstallationKindAllowed(Subject $subject, CredentialKind $kind): void
    {
        $this->assertAllowed($kind, $this->installationKinds($subject));
    }

    /**
     * @param  list<CredentialKind>  $defaults
     * @return list<CredentialKind>
     */
    private function kinds(Subject $subject, array $defaults): array
    {
        $kinds = $this->declaration instanceof DeclaresSelfServiceMintPolicy
            ? $this->declaration->selfServiceKinds($subject)
            : $defaults;

        return array_values(array_unique($kinds, SORT_REGULAR));
    }

    /** @param list<CredentialKind> $allowed */
    private function assertAllowed(CredentialKind $kind, array $allowed): void
    {
        if (! in_array($kind, $allowed, true)) {
            throw CredentialVerbRefused::selfServiceKind($kind);
        }
    }
}
