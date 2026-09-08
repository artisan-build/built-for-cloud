<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use Illuminate\Support\ServiceProvider;

final class StandaloneHarnessServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app['config']->set('auth.defaults.guard', 'web');
        $this->app['config']->set('auth.guards', []);
        $this->app['config']->set('auth.providers', []);
        $this->app['config']->set('cache.default', 'array');
        $this->app['config']->set('built-for-cloud.surfaces.data_migrations', false);
    }
}
