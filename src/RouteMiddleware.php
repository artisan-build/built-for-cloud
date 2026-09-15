<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final class RouteMiddleware
{
    /**
     * @param  list<string>  $middleware
     */
    public static function indexOfClass(array $middleware, string $class): ?int
    {
        foreach ($middleware as $index => $entry) {
            if (explode(':', $entry, 2)[0] === $class) {
                return $index;
            }
        }

        return null;
    }
}
