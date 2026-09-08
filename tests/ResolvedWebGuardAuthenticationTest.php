<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Exceptions\UnsupportedHumanAuthConfiguration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Orchestra\Testbench\TestCase as Orchestra;
use RuntimeException;

final class ResolvedWebGuardAuthenticationTest extends Orchestra
{
    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', [
            'driver' => 'session',
            'provider' => 'users',
        ]);
        $app['config']->set('auth.providers.users', [
            'driver' => 'eloquent',
            'model' => 'App\\Models\\User',
        ]);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('resolved-guard-key', 2)));
    }

    public function test_package_refuses_a_web_guard_resolved_with_the_laravel_default_model(): void
    {
        if (getenv('BFC_RESOLVED_WEB_GUARD_CHILD') !== '1') {
            $environment = getenv();
            $environment = is_array($environment) ? $environment : [];
            $environment['BFC_RESOLVED_WEB_GUARD_CHILD'] = '1';
            $process = proc_open(
                [
                    PHP_BINARY,
                    dirname(__DIR__).'/vendor/bin/pest',
                    __FILE__,
                    '--filter=test_package_refuses_a_web_guard_resolved_with_the_laravel_default_model',
                    '--colors=never',
                ],
                [
                    0 => ['pipe', 'r'],
                    1 => ['pipe', 'w'],
                    2 => ['pipe', 'w'],
                ],
                $pipes,
                dirname(__DIR__),
                $environment,
            );

            if (! is_resource($process)) {
                throw new RuntimeException('Could not start the isolated resolved-guard test process.');
            }

            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $error = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);

            $this->assertSame(0, proc_close($process), $output."\n".$error);

            return;
        }

        $this->assertFalse(class_exists('App\\Models\\User', false));
        $provider = Auth::guard('web')->getProvider();

        $this->assertInstanceOf(EloquentUserProvider::class, $provider);
        $this->assertSame('App\\Models\\User', $provider->getModel());

        try {
            $this->app->register(BuiltForCloudServiceProvider::class);
            $this->fail('Package registration should reject the cached foreign provider.');
        } catch (UnsupportedHumanAuthConfiguration $exception) {
            $this->assertSame(User::class, config('auth.providers.users.model'));
            $this->assertSame('App\\Models\\User', $provider->getModel());
            $this->assertStringContainsString('already-resolved web guard', $exception->getMessage());
        }
    }
}
