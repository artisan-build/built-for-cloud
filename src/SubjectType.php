<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/**
 * What one revocation costs. A subject type describes the blast radius of
 * killing a credential; it never grants anything by itself.
 */
enum SubjectType: string
{
    case Application = 'application';
    case Installation = 'installation';
    case UserPrincipal = 'user_principal';
    case ExternalConsumer = 'external_consumer';
    case Operator = 'operator';

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $type): string => $type->value,
            self::cases(),
        );
    }
}
