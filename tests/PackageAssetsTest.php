<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Blade;
use Orchestra\Testbench\TestCase as Orchestra;

final class PackageAssetsTest extends Orchestra
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
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('asset-test-key!!', 2)));
    }

    public function test_it_serves_the_compiled_stylesheet_from_the_package_with_a_long_lived_cache(): void
    {
        $response = $this->get('/bfc/assets/bfc.css');

        $response->assertOk();
        $this->assertStringStartsWith('text/css', (string) $response->headers->get('Content-Type'));
        $this->assertStringContainsString('immutable', (string) $response->headers->get('Cache-Control'));
        $this->assertStringContainsString('max-age=31536000', (string) $response->headers->get('Cache-Control'));
        $this->assertSame(file_get_contents(__DIR__.'/../resources/dist/bfc.css'), $response->streamedContent());
    }

    public function test_it_serves_every_bundled_font(): void
    {
        $fonts = glob(__DIR__.'/../resources/dist/fonts/*.woff2') ?: [];
        $this->assertNotEmpty($fonts);

        foreach ($fonts as $font) {
            $response = $this->get('/bfc/assets/fonts/'.basename($font));

            $response->assertOk();
            $this->assertSame('font/woff2', $response->headers->get('Content-Type'));
        }
    }

    public function test_it_serves_the_scalpels_wordmark(): void
    {
        $response = $this->get('/bfc/assets/img/scalpels-wordmark.webp');

        $response->assertOk();
        $this->assertSame('image/webp', $response->headers->get('Content-Type'));
    }

    public function test_it_serves_nothing_outside_the_bundled_assets(): void
    {
        foreach ([
            '/bfc/assets/missing.css',
            '/bfc/assets/fonts/missing.woff2',
            '/bfc/assets/../../composer.json',
            '/bfc/assets/%2e%2e/%2e%2e/composer.json',
            '/bfc/assets/fonts/..%2f..%2f..%2fcomposer.json',
            '/bfc/assets/dist/bfc.css',
            '/bfc/assets/img/missing.webp',
            '/bfc/assets/img/scalpels-wordmark.png',
        ] as $path) {
            $this->get($path)->assertNotFound();
        }
    }

    public function test_every_package_class_a_view_uses_is_in_the_compiled_stylesheet(): void
    {
        $css = (string) file_get_contents(__DIR__.'/../resources/dist/bfc.css');
        $views = glob(__DIR__.'/../resources/views/{,*/}*.blade.php', GLOB_BRACE) ?: [];
        $classes = [];

        foreach ($views as $view) {
            preg_match_all('/\\sclass="([^"]*)"/', (string) file_get_contents($view), $attributes);
            preg_match_all('/(?<![\\w-])bfc-[a-z-]+/', implode(' ', $attributes[1]), $matches);
            $classes = [...$classes, ...$matches[0]];
        }

        $this->assertContains('bfc-panel', $classes);

        $missing = array_values(array_filter(
            array_unique($classes),
            static fn (string $class): bool => ! str_contains($css, ".{$class}"),
        ));

        $this->assertSame([], $missing, 'Rebuild the stylesheet with `composer css`; these classes are missing from resources/dist/bfc.css: '.implode(', ', $missing));
    }

    public function test_the_default_layout_links_the_stylesheet_with_a_content_version(): void
    {
        $version = substr((string) md5_file(__DIR__.'/../resources/dist/bfc.css'), 0, 12);

        $html = Blade::render('<x-bfc-layout>Body</x-bfc-layout>');

        $this->assertStringContainsString('<link rel="stylesheet" href="'.url('/bfc/assets/bfc.css').'?v='.$version.'">', $html);
    }
}
