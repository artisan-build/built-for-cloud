<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\User;
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
            .'auth.providers.users to use '.User::class
            .'. Conflicting provider: '.$model.'. Remove the host-owned human model/configuration.',
        );
    }

    public static function forGuard(mixed $guard): self
    {
        return new self(
            'Built for Cloud owns the supported human auth guard and requires '
            .'auth.defaults.guard to select the web session guard backed by the users provider. '
            .'Conflicting guard: '.get_debug_type($guard).'. Remove the host-owned human guard configuration.',
        );
    }

    public static function forResolvedProvider(mixed $provider): self
    {
        $model = is_string($provider) ? $provider : get_debug_type($provider);

        return new self(
            'Built for Cloud cannot use the already-resolved web guard because its effective provider is '
            .$model.', not '.User::class.'. Resolve the guard only after package registration.',
        );
    }
}
