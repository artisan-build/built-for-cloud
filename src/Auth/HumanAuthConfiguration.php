<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Exceptions\UnsupportedHumanAuthConfiguration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Config\Repository;

final class HumanAuthConfiguration
{
    public static function apply(Repository $config): void
    {
        $provider = $config->get('auth.providers.users');
        $configuredModel = is_array($provider) ? ($provider['model'] ?? null) : null;
        $unmaterializedLaravelDefault = $configuredModel === 'App\\Models\\User' && ! class_exists($configuredModel);

        if ($provider !== null
            && (! is_array($provider)
                || ($provider['driver'] ?? null) !== 'eloquent'
                || (! $unmaterializedLaravelDefault
                    && $configuredModel !== User::class))) {
            throw UnsupportedHumanAuthConfiguration::forProvider($provider);
        }

        $config->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model' => User::class,
        ]);

        $defaultGuard = $config->get('auth.defaults.guard', 'web');

        if ($defaultGuard !== 'web') {
            throw UnsupportedHumanAuthConfiguration::forGuard($defaultGuard);
        }

        $guard = $config->get('auth.guards.web');

        if ($guard === null) {
            $config->set('auth.guards.web', [
                'driver' => 'session',
                'provider' => 'users',
            ]);

            return;
        }

        if (! is_array($guard)
            || ($guard['driver'] ?? null) !== 'session'
            || ($guard['provider'] ?? null) !== 'users') {
            throw UnsupportedHumanAuthConfiguration::forGuard($guard);
        }
    }
}
