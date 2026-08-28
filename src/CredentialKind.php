<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * How a credential authenticates. `bearer` and `basic` carry a sha256 secret
 * hash at rest. `asymmetric` rows carry a public key ONLY — never any secret
 * material. `hmac` is schema-supported; its crypto ships separately.
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
