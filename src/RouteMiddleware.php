<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final class RouteMiddleware
{
    /**
     * @param  list<mixed>  $middleware
     */
    public static function indexOfClass(array $middleware, string $class): ?int
    {
        foreach ($middleware as $index => $entry) {
            if (! is_string($entry)) {
                continue;
            }

            if (explode(':', $entry, 2)[0] === $class) {
                return $index;
            }
        }

        return null;
    }
}
