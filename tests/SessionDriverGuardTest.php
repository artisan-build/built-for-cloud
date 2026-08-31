<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Exceptions\UnsupportedSessionDriver;
use Illuminate\Foundation\Application;

final class SessionDriverGuardTest extends TestCase
{
    /** @var array<string, string> */
    private const array SESSION_DRIVERS = [
        'test_the_app_boots_with_cookie_sessions' => 'cookie',
        'test_the_app_boots_with_redis_sessions' => 'redis',
        'test_the_app_boots_with_array_sessions' => 'array',
        'test_the_app_boots_with_file_sessions' => 'file',
    ];

    private ?string $sessionDriver = null;

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set(
            'session.driver',
            $this->sessionDriver ?? self::SESSION_DRIVERS[$this->name()] ?? 'array',
        );
    }

    public function test_the_app_boots_with_cookie_sessions(): void
    {
        $this->assertSame('cookie', config('session.driver'));
    }

    public function test_the_app_boots_with_redis_sessions(): void
    {
        $this->assertSame('redis', config('session.driver'));
    }

    public function test_the_app_boots_with_array_sessions(): void
    {
        $this->assertSame('array', config('session.driver'));
    }

    public function test_the_app_boots_with_file_sessions(): void
    {
        $this->assertSame('file', config('session.driver'));
    }

    public function test_the_app_refuses_to_boot_with_the_database_session_driver(): void
    {
        $this->sessionDriver = 'database';

        $this->expectException(UnsupportedSessionDriver::class);
        $this->expectExceptionMessage(UnsupportedSessionDriver::DATABASE_MESSAGE);

        $this->refreshApplication();
    }
}
