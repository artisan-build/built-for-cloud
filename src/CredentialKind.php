<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * How a credential authenticates. `bearer` and `basic` carry a sha256 secret
 * hash at rest. `asymmetric` rows carry a public key ONLY — never any secret
 * material. `hmac` rows are per-subject symmetric signing secrets (PRD 1.21,
 * D9): the key is stored ENCRYPTED with a ciphertext key-version — see the
 * honest at-rest statement on {@see Credential} — lives a `pending → active`
 * lifecycle where exchange delivers and NEVER activates (SEC-V3-01), and
 * signs/verifies the canonical envelope (SEC-V3-07).
 */
enum CredentialKind: string
{
    case Bearer = 'bearer';
    case Basic = 'basic';
    case Asymmetric = 'asymmetric';
    case Hmac = 'hmac';

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $kind): string => $kind->value,
            self::cases(),
        );
    }
}
