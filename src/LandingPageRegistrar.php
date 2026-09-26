<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Controllers\LandingPage;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use RuntimeException;

final class LandingPageRegistrar
{
    public function mount(Router $router): Route
    {
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
                throw new RuntimeException('The public root route [GET /] is reserved by the built-for-cloud landing page; remove the host root route.');
            }
        }
    }
}
