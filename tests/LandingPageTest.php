<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Illuminate\Foundation\Application;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\View;
use Orchestra\Testbench\TestCase as Orchestra;

final class LandingPageTest extends Orchestra
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('built-for-cloud.ui.landing_page', true);
        $app['config']->set('built-for-cloud.manifest', [
            'name' => 'Test <App> & Company',
            'slug' => 'test-app',
            'description' => 'A "quoted" <strong>test</strong> & description.',
            'icon' => 'https://assets.example.test/icon.svg?size=2&kind=test',
            'product_url' => 'https://scalpels.app/products/test-app?ref=test&kind=app',
        ]);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('landing-test-key', 2)));
    }

    public function test_it_renders_one_structural_marker_and_escaped_test_value_for_each_landing_element(): void
    {
        $layoutRenders = 0;
        View::composer('bfc::layout', static function () use (&$layoutRenders): void {
            $layoutRenders++;
        });

        $route = $this->app['router']->getRoutes()->getByName('bfc.landing');
        $this->assertNotNull($route);
        $this->assertSame('/', $route->uri());
        $this->assertSame(['GET', 'HEAD'], $route->methods());

        $response = $this->get('/');
        $response->assertOk();
        $content = (string) $response->getContent();

        $this->assertSame(1, $layoutRenders);
        $this->assertSame(1, substr_count($content, '<main>'));
        $document = new \DOMDocument;
        $this->assertTrue(@$document->loadHTML($content));
        $landingInsideLayout = (new \DOMXPath($document))->query('//main/section[@data-testid="landing"]');
        $this->assertNotFalse($landingInsideLayout);
        $this->assertSame(1, $landingInsideLayout->length);

        foreach ([
            'landing',
            'landing-manifest-icon',
            'landing-manifest-name',
            'landing-manifest-description',
            'landing-manifest-product-link',
            'landing-ui-entry',
        ] as $testId) {
            $this->assertSame(1, substr_count($content, 'data-testid="'.$testId.'"'));
        }

        foreach ([
            'Test <App> & Company',
            'A "quoted" <strong>test</strong> & description.',
            'https://assets.example.test/icon.svg?size=2&kind=test',
            'https://scalpels.app/products/test-app?ref=test&kind=app',
        ] as $value) {
            $response->assertSee($value);
            $response->assertDontSee($value, false);
        }

        $response->assertSee('test-app');
    }

    public function test_match_time_ownership_refuses_a_late_root_takeover_before_the_host_handler(): void
    {
        $hostRuns = 0;

        /** @var Router $router */
        $router = $this->app['router'];
        $router->get('/', static function () use (&$hostRuns): string {
            $hostRuns++;

            return 'host-root';
        })->name('host.root');

        $this->withoutExceptionHandling();

        try {
            $this->get('/');
            $this->fail('The late root takeover was served.');
        } catch (\RuntimeException $exception) {
            $this->assertStringContainsString('reserved by the built-for-cloud landing page', $exception->getMessage());
        }

        $this->assertSame(0, $hostRuns);
    }

    public function test_cached_boot_and_match_checks_retain_landing_ownership(): void
    {
        /** @var Router $router */
        $router = $this->app['router'];
        $ownedLanding = $router->getRoutes()->getByName('bfc.landing');
        $this->assertNotNull($ownedLanding);
        $router->setCompiledRoutes($router->getRoutes()->compile());

        $this->assertInstanceOf(CompiledRouteCollection::class, $router->getRoutes());
        StandaloneRouteOwnership::assertOwned($router, [$ownedLanding]);
        $this->get('/')->assertOk()->assertSeeHtml('data-testid="landing"');

        $hostRuns = 0;
        $router->get('/', static function () use (&$hostRuns): string {
            $hostRuns++;

            return 'cached-host-root';
        })->name('cached.host-root');

        try {
            $this->withoutExceptionHandling()->get('/');
            $this->fail('The cached root takeover was served.');
        } catch (\RuntimeException $exception) {
            $this->assertStringContainsString('reserved by the built-for-cloud landing page', $exception->getMessage());
        }

        $this->assertSame(0, $hostRuns);
    }
}
