<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\Dashboards\AppDashboardComponent;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\Dashboards\AppDashboardController;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\Attributes\DefineEnvironment;

final class DashboardTest extends TestCase
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

    /** @param Application $app */
    protected function useAppDashboardController($app): void
    {
        $app['config']->set('built-for-cloud.dashboard', AppDashboardController::class);
    }

    /** @param Application $app */
    protected function useAppDashboardComponent($app): void
    {
        $app['config']->set('built-for-cloud.dashboard', AppDashboardComponent::class);
    }

    public function test_the_default_dashboard_offers_general_prompts_for_the_scalpels_mcp(): void
    {
        $response = $this->actingAsVersioned($this->owner())->get('/dashboard');

        $response->assertOk()
            ->assertSeeHtml('data-testid="dashboard"')
            ->assertDontSeeHtml('data-testid="dashboard-settings"')
            ->assertSeeHtml('data-testid="dashboard-prompt-copy"')
            ->assertSee('Does anything need my attention?')
            ->assertSee('Call `installed_apps`', escape: false);
        $this->assertSame('/dashboard', route('bfc.dashboard', absolute: false));
    }

    public function test_the_default_dashboard_shows_the_prompts_an_app_declares_behind_the_same_opening(): void
    {
        config(['built-for-cloud.dashboard_prompts' => [
            ['title' => 'Slowest endpoints', 'ask' => 'List my slowest endpoints this week.'],
            ['title' => 'Malformed', 'prompt' => 'missing its ask'],
        ]]);

        $response = $this->actingAsVersioned($this->owner())->get('/dashboard');

        $response->assertOk()
            ->assertSee('Slowest endpoints')
            ->assertSee('then call `app_tools` to see what it offers. List my slowest endpoints this week.', escape: false)
            ->assertDontSee('Malformed')
            ->assertDontSee('Does anything need my attention?');
    }

    public function test_a_signed_out_visitor_is_sent_to_sign_in_and_back_to_the_dashboard(): void
    {
        $this->get('/dashboard')->assertRedirect(route('bfc.login', ['intended' => '/dashboard']));
    }

    public function test_signing_in_lands_on_the_dashboard(): void
    {
        $owner = $this->owner();

        $this->post('/bfc/login', ['email' => $owner->email, 'password' => 'test-created-password'])
            ->assertRedirect('/dashboard');
    }

    public function test_the_landing_page_opens_the_dashboard(): void
    {
        $this->get('/')->assertOk()->assertSeeHtml('href="'.route('bfc.dashboard').'"');
    }

    public function test_settings_lives_at_settings_and_not_under_bfc(): void
    {
        $this->assertSame('/settings', route('bfc.ui.home', absolute: false));
        $owner = $this->owner();
        $this->actingAsVersioned($owner)->get('/settings')->assertOk()->assertSeeHtml('data-testid="ui-shell"');
        $this->actingAsVersioned($owner)->get('/bfc/ui')->assertNotFound();
    }

    #[DefineEnvironment('useAppDashboardController')]
    public function test_an_app_can_put_its_own_controller_behind_the_dashboard(): void
    {
        $this->get('/dashboard')->assertRedirect();
        $this->actingAsVersioned($this->owner())->get('/dashboard')->assertOk()->assertSee('app-dashboard-controller');
    }

    #[DefineEnvironment('useAppDashboardComponent')]
    public function test_an_app_can_put_a_full_page_livewire_component_behind_the_dashboard(): void
    {
        $this->get('/dashboard')->assertRedirect();
        $this->actingAsVersioned($this->owner())->get('/dashboard')
            ->assertOk()
            ->assertSeeHtml('data-testid="app-dashboard-component"')
            ->assertSeeHtml('data-testid="bfc-layout"');
    }

    private function owner(): User
    {
        $user = User::query()->create([
            'name' => 'Test-created owner',
            'email' => 'dashboard-owner@example.test',
            'password' => Hash::make('test-created-password'),
        ]);
        $user->forceFill([
            'role' => UserRole::Owner->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => 'dashboard-owner@example.test',
        ])->save();

        return $user;
    }
}
