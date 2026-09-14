<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Controllers\LandingPage;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use RuntimeException;

final class LandingPageRegistrar
{
    public function mount(Router $router): ?Route
    {
        if (config('built-for-cloud.ui.landing_page') !== true) {
            return null;
        }

        $this->assertRootIsAvailable($router);
        LandingManifest::fromConfiguration();

        return $router->get('/', LandingPage::class)->name('bfc.landing');
    }

    private function assertRootIsAvailable(Router $router): void
    {
        foreach ($router->getRoutes()->getRoutes() as $route) {
            $rootCollision = $route->getDomain() === null
                && $route->uri() === '/'
                && array_intersect($route->methods(), ['GET', 'HEAD']) !== [];

            if ($rootCollision || $route->getName() === 'bfc.landing') {
                throw new RuntimeException('The public root route [GET /] is reserved by the enabled built-for-cloud landing page; remove the host root route before enabling it.');
            }
        }
    }
}
