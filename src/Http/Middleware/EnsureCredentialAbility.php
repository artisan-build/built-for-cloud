<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires the authenticated credential to hold an explicit ability. FAILS
 * CLOSED: a credential with null or empty abilities is denied everything,
 * and a route registering this middleware without an ability string is a
 * configuration error, not an open door.
 *
 * Usage: `->middleware('bfc.ability:credential:read')`.
 */
final class EnsureCredentialAbility
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly CredentialDeclaration $declaration,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $ability = null): Response
    {
        if ($ability === null || $ability === '') {
            throw new InvalidArgumentException(
                'The bfc.ability middleware requires an explicit ability string.',
            );
        }

        $guardName = (string) config('built-for-cloud.credentials.guard', 'bfc');
        $guard = $this->auth->guard($guardName);

        if (! $guard instanceof CredentialGuard) {
            throw new InvalidArgumentException(
                "The [{$guardName}] guard is not a built-for-cloud credential guard.",
            );
        }

        if ($guard->guest()) {
            abort(401);
        }

        $credential = $guard->credential();

        if ($credential === null || ! $credential->hasAbility($ability)) {
            abort(403);
        }

        if (! $this->declaration->authorize($credential, $ability, $request)) {
            abort(403);
        }

        return $next($request);
    }
}
