<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\RouteMiddleware;

it('ignores non-string entries while finding an exact parameterized middleware class', function (): void {
    $middleware = [
        static fn (): null => null,
        AuthenticateMcp::class.'Foo:product',
        AuthenticateMcp::class.':product',
    ];

    expect(RouteMiddleware::indexOfClass($middleware, AuthenticateMcp::class))->toBe(2);
});
