<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Exceptions\UnsupportedHumanAuthConfiguration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Auth\User as FrameworkUser;

final class HumanAuthConfiguration
{
    public static function apply(Repository $config): void
    {
        $provider = $config->get('auth.providers.users');
        $configuredModel = is_array($provider) ? ($provider['model'] ?? null) : null;
        $unmaterializedLaravelDefault = $configuredModel === 'App\\Models\\User' && ! class_exists($configuredModel);
        $frameworkTestbenchDefault = $configuredModel === FrameworkUser::class;

        if ($provider !== null
            && (! is_array($provider)
                || ($provider['driver'] ?? null) !== 'eloquent'
                || (! $unmaterializedLaravelDefault
                    && ! $frameworkTestbenchDefault
                    && $configuredModel !== User::class))) {
            throw UnsupportedHumanAuthConfiguration::forProvider($provider);
        }

        $config->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model' => User::class,
        ]);

        $defaultGuard = $config->get('auth.defaults.guard', 'web');
        $guard = is_string($defaultGuard) ? $config->get('auth.guards.'.$defaultGuard) : null;

        if (! is_array($guard)
            || ($guard['driver'] ?? null) !== 'session'
            || ($guard['provider'] ?? null) !== 'users') {
            throw UnsupportedHumanAuthConfiguration::forProvider($guard);
        }
    }
}
