<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use Illuminate\Routing\Router;

/**
 * The deployment-declared MCP surface advertised by `/bfc/meta`.
 *
 * ONE CONDITION, where the package can hold it. `mcp-serve` and
 * `endpoints.mcp` ride the declared path alone. `mcp-delegated` makes
 * a stronger promise — the advertised endpoint accepts a delegated
 * console assertion — and the half of that promise the package CAN
 * observe is verified rather than trusted: the router is asked whether
 * the route at the declared path is actually guarded by
 * {@see AuthenticateMcp}, so the capability and the middleware can
 * never disagree, which is precisely what `console-enter` holds by
 * riding the resolved-guard condition.
 *
 * The other half — that the product runs the delegated-tool conformance
 * assertion in its own suite — the package CANNOT observe, and does not
 * pretend to: it is a product declaration, in the same voice
 * `console-chrome-assets` uses to say that whether a page wears the
 * chrome is the application's own decision. A deployment that sets
 * `delegated` and never runs the assertion advertises truthfully-by-
 * config and falsely-in-fact; the contract document says so plainly.
 *
 * Pinned by `tests/McpMetadataTest.php` — "advertises delegated MCP
 * only when the declared path is actually guarded" and "does not
 * advertise delegated MCP for a route the middleware does not guard".
 */
final class McpConfiguration
{
    /**
     * The middleware alias the package registers for
     * {@see AuthenticateMcp} — the alias half of the guard check; a
     * route may mount either the alias or the class itself.
     */
    private const string MIDDLEWARE_ALIAS = 'bfc.mcp';

    public static function endpoint(): ?string
    {
        $path = config('built-for-cloud.mcp.path');

        if (! is_string($path) || preg_match('/^\/(?!\/)[^\s?#]*\z/u', $path) !== 1) {
            return null;
        }

        return $path;
    }

    public static function serves(): bool
    {
        return self::endpoint() !== null;
    }

    public static function delegated(): bool
    {
        if (! self::serves() || ! (bool) config('built-for-cloud.mcp.delegated', false)) {
            return false;
        }

        return self::advertisedEndpointIsGuarded();
    }

    /**
     * Whether the route at the advertised path carries this package's
     * MCP authentication. The check reads the ROUTER, not the
     * declaration, so a route that is missing, unmounted, or guarded by
     * something else does not earn the capability however the config is
     * set.
     *
     * The residue, named: a deployment mounting the same middleware
     * under an alias of its own reads as UNGUARDED here, because the
     * gathered middleware carries neither this alias nor the class —
     * the capability is then understated, never overstated, which is
     * the honest direction for this mechanism to fail in.
     */
    private static function advertisedEndpointIsGuarded(): bool
    {
        $uri = rtrim(ltrim((string) self::endpoint(), '/'), '/');

        $router = app('router');

        if (! $router instanceof Router) {
            return false;
        }

        foreach ($router->getRoutes() as $route) {
            if ($route->uri() === $uri) {
                $middleware = $route->gatherMiddleware();

                if (in_array(AuthenticateMcp::class, $middleware, true)
                    || in_array(self::MIDDLEWARE_ALIAS, $middleware, true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
