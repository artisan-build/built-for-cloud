<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

enum Scope: string
{
    case Consume = 'consume';
    case Admin = 'admin';
    case Onboard = 'onboard';

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $scope): string => $scope->value,
            self::cases(),
        );
    }
}
