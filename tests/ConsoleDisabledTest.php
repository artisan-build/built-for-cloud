<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use InvalidArgumentException;

/**
 * ADVISORY 6 / AC27 — the Console is OFF unless a deployment asks for it,
 * and a deployment that has not asked cannot be broken by it.
 *
 * This app is the ordinary upgrade case: it installs the package, has NOT
 * enabled the Console, and — as the collision that fails loudly when the
 * Console IS on — already owns an auth provider named
 * `bfc-console-actors`. It must boot, serve, and behave exactly as it did
 * before the Console existed.
 *
 * PHPUnit-style because the flag and the colliding provider have to be in
 * place before the package boots; a per-test config attribute is too
 * late.
 */
final class ConsoleDisabledTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('built-for-cloud.console.enabled', false);
        $app['config']->set('auth.providers.'.ConsoleGuardConfiguration::PROVIDER, [
            'driver' => 'eloquent',
            'model' => User::class,
        ]);
    }

    public function test_it_boots_with_the_reserved_provider_name_already_taken(): void
    {
        // Reaching this line at all is the assertion: the application
        // booted. An unconditional hard failure here would have turned a
        // package upgrade into a dead deployment.
        $this->assertSame(
            ['driver' => 'eloquent', 'model' => User::class],
            config('auth.providers.'.ConsoleGuardConfiguration::PROVIDER),
        );
    }

    public function test_it_injects_no_delegated_guard(): void
    {
        $this->assertNull(config('auth.guards.'.ConsoleGuardConfiguration::GUARD));

        $this->expectException(InvalidArgumentException::class);

        auth(ConsoleGuardConfiguration::GUARD);
    }

    public function test_the_session_gates_behave_exactly_as_they_did_before_the_console(): void
    {
        Route::middleware([StartSession::class, 'bfc.auth'])->get('/disabled-auth', fn (): array => ['ok' => true]);
        Route::middleware([StartSession::class, 'bfc.admin'])->get('/disabled-admin', fn (): array => ['ok' => true]);

        $user = User::query()->create([
            'name' => 'Local User',
            'email' => 'local@example.com',
            'password' => 'irrelevant',
        ]);

        $this->getJson('/disabled-auth')->assertStatus(401);
        $this->getJson('/disabled-admin')->assertStatus(403);

        $this->actingAs($user);

        $this->getJson('/disabled-auth')->assertOk();
        $this->getJson('/disabled-admin')->assertStatus(403);

        $user->forceFill(['is_admin' => true])->save();

        $this->getJson('/disabled-admin')->assertOk();
    }

    public function test_the_console_gate_refuses_rather_than_erroring(): void
    {
        Route::middleware([StartSession::class, 'bfc.console'])->get('/disabled-console', fn (): array => ['ok' => true]);

        $this->getJson('/disabled-console')
            ->assertStatus(401)
            ->assertHeader('BFC-Console-Reentry', '1')
            ->assertJsonPath('reason', 'not_authenticated');
    }
}
