<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

final class UnsupportedHumanAuthConfiguration extends RuntimeException
{
    public static function forProvider(mixed $provider): self
    {
        $model = is_array($provider) && is_string($provider['model'] ?? null)
            ? $provider['model']
            : get_debug_type($provider);

        return new self(
            'Built for Cloud owns the supported human auth provider and requires '
            .'auth.providers.users to use '.\ArtisanBuild\BuiltForCloud\User::class
            .'. Conflicting provider: '.$model.'. Remove the host-owned human model/configuration.',
        );
    }
}
