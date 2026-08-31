<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleReentryComponent;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Livewire\Drawer\Utils;
use Livewire\LivewireManager;
use Livewire\LivewireServiceProvider;

final class ConsoleLivewireReentryTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LivewireServiceProvider::class, BuiltForCloudServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        app(LivewireManager::class)->component('console-reentry-transport', ConsoleReentryComponent::class);

        Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
            ->get('/console-livewire', fn (): string => Blade::render('<livewire:console-reentry-transport />'));
    }

    public function test_a_capped_livewire_update_receives_the_structured_reentry_response(): void
    {
        config(['built-for-cloud.console.reentry_url' => 'https://scalpels.test/console/enter']);

        $actor = consoleActor();
        $freshSession = consoleSessionState($actor);

        $page = $this->withSession($freshSession)->get('/console-livewire')->assertOk();
        $snapshot = Utils::extractAttributeDataFromHtml($page->getContent(), 'wire:snapshot');

        Auth::forgetGuards();

        $this->withSession(consoleSessionState(
            $actor,
            CarbonImmutable::now()->subMinutes(121)->getTimestamp(),
        ));

        $this->postJson(app(LivewireManager::class)->getUpdateUri(), [
            'components' => [[
                'snapshot' => json_encode($snapshot, JSON_THROW_ON_ERROR),
                'updates' => [],
                'calls' => [[
                    'path' => '',
                    'method' => '$refresh',
                    'params' => [],
                ]],
            ]],
            'return_to' => '/admin/orders?page=2',
        ], ['X-Livewire' => 'true'])
            ->assertStatus(401)
            ->assertHeader('BFC-Console-Reentry', '1')
            ->assertExactJson([
                'version' => 1,
                'error' => 'console_reentry_required',
                'reason' => 'assertion_age_cap',
                'reentry_url' => 'https://scalpels.test/console/enter',
                'return_to' => '/admin/orders?page=2',
            ]);
    }
}
