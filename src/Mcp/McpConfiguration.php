<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Throwable;

/**
 * The deployment-declared MCP surface advertised by `/bfc/meta`.
 *
 * ONE CONDITION, where the package can hold it. `mcp-serve` and
 * `endpoints.mcp` ride the declared path alone. `mcp-delegated` makes
 * a stronger promise — the advertised endpoint accepts a delegated
 * console assertion — and the half of that promise the package CAN
 * observe is verified rather than trusted: the router is asked for the
 * route that would actually HANDLE the MCP POST at the declared path
 * on the metadata request's own host, and that route's EFFECTIVE
 * middleware — gathered the way Laravel will run it, so middleware
 * groups are expanded, aliases resolve to their classes, and
 * `withoutMiddleware` exclusions are honoured. A guarded route of
 * another verb, another domain, or another path beside an unguarded
 * POST transport does not earn the capability, and neither does a
 * guard that was declared and then excluded.
 *
 * What the check ESTABLISHES is one-directional, and only that
 * direction is claimed: when the capability is advertised, the route
 * Laravel would dispatch for that POST carries this middleware in its
 * effective pipeline. What still escapes it: a deployment whose MCP
 * route is domain-qualified on a host other than the one the metadata
 * request arrived on reads as unguarded here (the capability is then
 * UNDERSTATED — withheld, never falsely granted, which is the honest
 * direction for this mechanism to fail in); a fallback route, which is
 * the 404 handler rather than the transport; and the other half of the
 * promise entirely.
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
 * only when the declared path is actually guarded", "does not
 * advertise delegated MCP for a route the middleware does not guard",
 * "does not advertise delegated MCP beside a guarded route of another
 * verb or domain", "withholds delegated MCP when the guard is declared
 * and then excluded" and "earns delegated MCP for a guarded route at
 * the root path".
 */
final class McpConfiguration
{
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
     * Whether the route Laravel would DISPATCH for the MCP POST at the
     * advertised path carries this package's MCP authentication in its
     * effective pipeline.
     *
     * The route is selected by MATCHING, not by comparing URI text, so
     * verb and domain decide it the way they decide the real request —
     * a guarded GET decoy or another deployment's domain cannot stand
     * in for an unguarded POST transport. The middleware is read
     * through the router's own gatherer, so groups, aliases and
     * exclusions resolve exactly as the pipeline will run them. The
     * root path `/` needs no special case: it is handed to the matcher
     * verbatim and matches the root route the framework registers.
     *
     * The residue, named: no route at all (including a method-not-
     * allowed POST) reads as unguarded, and a domain-qualified MCP
     * route on a host other than the metadata request's reads the same
     * way — withheld, never granted.
     */
    private static function advertisedEndpointIsGuarded(): bool
    {
        $router = app('router');

        if (! $router instanceof Router) {
            return false;
        }

        try {
            $route = $router->getRoutes()->match(self::mcpPostProbe());
        } catch (Throwable) {
            return false;
        }

        return in_array(AuthenticateMcp::class, $router->gatherRouteMiddleware($route), true);
    }

    /**
     * The request the MCP transport itself would present: a POST at
     * the advertised path, on the host this deployment is answering
     * metadata on (so a domain-qualified route must qualify against
     * the host that actually serves this request, not merely share the
     * URI text).
     */
    private static function mcpPostProbe(): Request
    {
        $current = app('request');

        $host = $current instanceof Request && $current->getHost() !== ''
            ? $current->getHost()
            : 'localhost';

        return Request::create('http://'.$host.(string) self::endpoint(), 'POST');
    }
}
