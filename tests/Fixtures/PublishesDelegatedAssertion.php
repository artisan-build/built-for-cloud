<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Console\AssertionPurpose;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Publishes a verified delegated request assertion on the request it
 * fronts, the way the MCP middleware does, so a test vector can drive
 * the gates' delegated-principal refusals through a REAL dispatched
 * request. A pipeline middleware is the only place to do this from:
 * the container's request binding is swapped for each dispatched route
 * request, so an attribute pre-published on the bound instance never
 * reaches the route.
 */
final class PublishesDelegatedAssertion
{
    public function __invoke(Request $request, Closure $next): Response
    {
        RequestAssertion::publish(
            $request,
            consoleActor(subject: 'fixture-delegated-'.bin2hex(random_bytes(4)), onBehalfOf: 'Acme Agency'),
            consoleAssertionFor(onBehalfOf: 'Acme Agency', purpose: AssertionPurpose::Mcp),
        );

        return $next($request);
    }
}
