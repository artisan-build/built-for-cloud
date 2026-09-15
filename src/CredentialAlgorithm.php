<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

enum CredentialAlgorithm: string
{
    case Rs256 = 'RS256';
    case HmacSha256 = HmacEnvelope::ALGORITHM;

    public static function forKind(CredentialKind $kind): self
    {
        return match ($kind) {
            CredentialKind::Asymmetric => self::Rs256,
            CredentialKind::Hmac => self::HmacSha256,
            default => throw InvalidCredentialInput::boundKindNotAllowed(),
        };
    }
}
