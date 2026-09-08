<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;

final class SessionDriverGuardTest extends TestCase
{
    /** @var array<string, string> */
    private const array SESSION_DRIVERS = [
        'test_the_app_boots_and_serves_requests_with_cookie_sessions' => 'cookie',
        'test_the_app_boots_and_serves_requests_with_redis_sessions' => 'redis',
        'test_the_app_boots_and_serves_requests_with_array_sessions' => 'array',
        'test_the_app_boots_and_serves_requests_with_file_sessions' => 'file',
        'test_the_app_boots_and_runs_artisan_with_the_database_session_driver' => 'database',
        'test_a_request_uses_the_database_session_driver' => 'database',
    ];

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set(
            'session.driver',
            self::SESSION_DRIVERS[$this->name()] ?? 'array',
        );
    }

    public function test_the_app_boots_and_serves_requests_with_cookie_sessions(): void
    {
        $this->assertSame('cookie', config('session.driver'));
        $this->assertRequestSucceeds();
    }

    public function test_the_app_boots_and_serves_requests_with_redis_sessions(): void
    {
        $this->assertSame('redis', config('session.driver'));
        $this->assertRequestSucceeds();
    }

    public function test_the_app_boots_and_serves_requests_with_array_sessions(): void
    {
        $this->assertSame('array', config('session.driver'));
        $this->assertRequestSucceeds();
    }

    public function test_the_app_boots_and_serves_requests_with_file_sessions(): void
    {
        $this->assertSame('file', config('session.driver'));
        $this->assertRequestSucceeds();
    }

    public function test_the_app_boots_and_runs_artisan_with_the_database_session_driver(): void
    {
        $this->assertTrue($this->app->isBooted());
        $this->assertSame('database', config('session.driver'));
        $this->artisan('list')->assertSuccessful();
    }

    public function test_a_request_uses_the_database_session_driver(): void
    {
        $this->assertRequestSucceeds();
    }

    private function assertRequestSucceeds(): void
    {
        Route::get('/session-driver-probe', fn () => response()->noContent());

        $this->getJson('/session-driver-probe')->assertNoContent();
    }
}
