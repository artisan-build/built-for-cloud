<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class ClassBoundRouteOwnership
{
    public static function operatorGateForAction(string $action): string
    {
        return match ($action) {
            'fixture' => ClassBoundCredentialGate::class,
            default => ClassBoundCredentialGate::class,
        };
    }
}
