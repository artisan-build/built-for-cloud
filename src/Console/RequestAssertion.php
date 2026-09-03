<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Illuminate\Http\Request;
use SensitiveParameter;

/**
 * The delegated principal published by one verified MCP assertion.
 *
 * The request object is the store and the scope. Nothing is retained on
 * this class or in the container, so a long-lived worker cannot hand one
 * request's assertion principal to the next request.
 *
 * Pinned by `tests/AuthenticateMcpTest.php` — "authenticates a
 * TokenRegistry bearer and does not leak the prior request assertion memo".
 */
final class RequestAssertion
{
    private const string ATTRIBUTE = 'bfc.request_assertion_principal';

    public static function publish(#[SensitiveParameter] Request $request, DelegatedActor $actor, Assertion $assertion): ActingPrincipal
    {
        $principal = ActingPrincipal::delegatedRequest(
            $actor,
            new DelegatedClaims(
                displayName: $assertion->displayName,
                role: $assertion->role,
                onBehalfOf: $assertion->onBehalfOf,
            ),
        );

        $request->attributes->set(self::ATTRIBUTE, $principal);
        $request->setUserResolver(static fn (): DelegatedActor => $actor);

        return $principal;
    }

    public static function principal(#[SensitiveParameter] Request $request): ?ActingPrincipal
    {
        $principal = $request->attributes->get(self::ATTRIBUTE);

        return $principal instanceof ActingPrincipal ? $principal : null;
    }
}
