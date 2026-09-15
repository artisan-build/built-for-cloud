<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Runtime counters immediately before the real package MCP authentication gate. */
final class ContractMajorLiveAuthenticationProbe
{
    public function __construct(
        private readonly CredentialResolver $credentials,
        private readonly ContractMajorLiveReplayStore $replay,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        ContractMajorLiveState::increment('authentication_entries');
        ContractMajorLiveState::increment('credential_resolver_invocations');

        $credential = $this->credentials->resolve(CredentialKind::Bearer, $request->bearerToken());

        if ($credential !== null) {
            $key = 'test-created-contract-major-replay-probe';

            if (! $this->replay->has($key)) {
                $this->replay->put($key);
            }
        }

        return $next($request);
    }
}
