<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\Layouts\CustomLayout;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\Layouts\FullPageLivewireComponent;
use ArtisanBuild\BuiltForCloud\View\Layout;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use Orchestra\Testbench\TestCase as Orchestra;

final class LayoutTest extends Orchestra
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [LivewireServiceProvider::class, BuiltForCloudServiceProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('built-for-cloud.manifest', [
            'name' => 'Layout Test App',
            'slug' => 'layout-test-app',
            'description' => 'An app used to test the layout.',
            'icon' => 'https://assets.example.test/icon.svg',
            'product_url' => 'https://scalpels.app/products/layout-test-app',
        ]);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('layout-test-key!', 2)));
    }

    /** @param Application $app */
    protected function useCustomLayout($app): void
    {
        $app['config']->set('built-for-cloud.layout', CustomLayout::class);
        $app['view']->addNamespace('layout-fixtures', __DIR__.'/Fixtures/views');
    }

    /** @param Application $app */
    protected function optOutOfTheLivewireLayout($app): void
    {
        $app['config']->set('built-for-cloud.livewire_layout', false);
        $app['config']->set('livewire.component_layout', 'layouts::app');
    }

    public function test_the_package_layout_class_is_the_default_for_blade_and_livewire(): void
    {
        $this->assertSame(Layout::class, config('built-for-cloud.layout'));
        $this->assertSame(Layout::class, config('livewire.component_layout'));
    }

    public function test_the_published_config_reads_the_layout_from_the_environment(): void
    {
        $source = (string) file_get_contents(__DIR__.'/../config/built-for-cloud.php');

        $this->assertStringContainsString("env('BUILT_FOR_CLOUD_LAYOUT', Layout::class)", $source);
        $this->assertStringContainsString("env('BUILT_FOR_CLOUD_LIVEWIRE_LAYOUT', true)", $source);
    }

    public function test_an_app_blade_view_can_wrap_itself_in_the_layout_component(): void
    {
        $html = Blade::render('<x-bfc-layout title="App page"><p data-testid="app-body">Body</p></x-bfc-layout>');

        $this->assertStringContainsString('data-testid="bfc-layout"', $html);
        $this->assertStringContainsString('<title>App page</title>', $html);
        $this->assertStringContainsString('<p data-testid="app-body">Body</p>', $html);
    }

    public function test_the_layout_falls_back_to_the_app_name_when_no_title_is_given(): void
    {
        config(['app.name' => 'Fallback Name']);

        $html = Blade::render('<x-bfc-layout>Body</x-bfc-layout>');

        $this->assertStringContainsString('<title>Fallback Name</title>', $html);
    }

    public function test_the_header_is_scalpels_own_navigation_with_the_current_app(): void
    {
        $html = Blade::render('<x-bfc-layout>Body</x-bfc-layout>');

        $this->assertMatchesRegularExpression('/<a href="https:\/\/scalpels\.app\/dashboard"\s+data-testid="bfc-header-scalpels"/', $html);
        $this->assertMatchesRegularExpression('/<a href="https:\/\/scalpels\.app\/docs"\s+data-testid="bfc-header-docs"/', $html);
        $this->assertStringContainsString('data-testid="bfc-header-app"', $html);
        $this->assertStringContainsString('src="https://scalpels.app/img/products/transparent/layout-test-app.png"', $html);
    }

    public function test_the_user_menu_appears_only_for_a_signed_in_person(): void
    {
        $this->assertStringNotContainsString('data-testid="bfc-user-menu"', Blade::render('<x-bfc-layout>Body</x-bfc-layout>'));
    }

    public function test_pushed_head_and_script_stacks_reach_the_layout(): void
    {
        $html = Blade::render(<<<'BLADE'
            <x-bfc-layout title="Stacks">
                @push('head')<meta name="pushed-head">@endpush
                @push('scripts')<script data-testid="pushed-script"></script>@endpush
                Body
            </x-bfc-layout>
            BLADE);

        $this->assertMatchesRegularExpression('/<meta name="pushed-head">.*<\/head>/s', $html);
        $this->assertMatchesRegularExpression('/<script data-testid="pushed-script"><\/script>\s*<\/body>/s', $html);
    }

    public function test_package_pages_render_inside_the_default_layout(): void
    {
        $response = $this->get('/');

        $response->assertOk()
            ->assertSeeHtml('data-testid="bfc-layout"')
            ->assertSeeHtml('<title>Layout Test App</title>')
            ->assertSeeHtml('data-testid="landing"');
    }

    public function test_full_page_livewire_components_render_inside_the_default_layout(): void
    {
        Route::get('/full-page', FullPageLivewireComponent::class);

        $response = $this->get('/full-page');

        $response->assertOk()
            ->assertSeeHtml('data-testid="bfc-layout"')
            ->assertSeeHtml('<title>Full page</title>')
            ->assertSeeHtml('data-testid="full-page-livewire"');
    }

    #[DefineEnvironment('useCustomLayout')]
    public function test_a_configured_layout_class_replaces_the_package_layout_for_package_pages(): void
    {
        $response = $this->get('/');

        $response->assertOk()
            ->assertSeeHtml('data-testid="custom-layout"')
            ->assertSeeHtml('<title>custom: Layout Test App</title>')
            ->assertSeeHtml('data-testid="landing"')
            ->assertDontSeeHtml('data-testid="bfc-layout"');
    }

    #[DefineEnvironment('useCustomLayout')]
    public function test_a_configured_layout_class_replaces_the_package_layout_for_full_page_livewire(): void
    {
        Route::get('/full-page', FullPageLivewireComponent::class);

        $response = $this->get('/full-page');

        $response->assertOk()
            ->assertSeeHtml('data-testid="custom-layout"')
            ->assertSeeHtml('<title>custom: Full page</title>')
            ->assertSeeHtml('data-testid="full-page-livewire"')
            ->assertDontSeeHtml('data-testid="bfc-layout"');
    }

    public function test_a_layout_change_reaches_views_compiled_before_it(): void
    {
        $this->get('/')->assertOk()->assertSeeHtml('data-testid="bfc-layout"');

        config(['built-for-cloud.layout' => CustomLayout::class]);
        $this->app['view']->addNamespace('layout-fixtures', __DIR__.'/Fixtures/views');

        $this->get('/')->assertOk()
            ->assertSeeHtml('data-testid="custom-layout"')
            ->assertDontSeeHtml('data-testid="bfc-layout"');
    }

    public function test_a_layout_that_is_not_a_blade_component_is_refused_by_name(): void
    {
        config(['built-for-cloud.layout' => \stdClass::class]);

        $this->expectExceptionMessage('BUILT_FOR_CLOUD_LAYOUT [stdClass] must name a class extending Illuminate\\View\\Component.');

        Blade::render('<x-bfc-layout>Body</x-bfc-layout>');
    }

    #[DefineEnvironment('optOutOfTheLivewireLayout')]
    public function test_an_app_can_keep_its_own_livewire_layout(): void
    {
        $this->assertSame('layouts::app', config('livewire.component_layout'));
        $this->assertStringContainsString('data-testid="bfc-layout"', Blade::render('<x-bfc-layout>Body</x-bfc-layout>'));
    }
}
