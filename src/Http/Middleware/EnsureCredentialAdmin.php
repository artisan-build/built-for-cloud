<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The gate on the unified store's own verb routes (`/bfc/credentials`):
 * accepts EITHER a legacy admin `api_tokens` row (exactly what
 * {@see EnsureAdminToken} accepts, unchanged) OR a unified-store `bearer`
 * credential with the `operator` subject holding {@see self::ABILITY} —
 * which is what the installer mints (PRD 1.20). Without the second branch
 * the install-time credential would be 401 on the one surface it exists to
 * manage.
 *
 * Which store authenticated is visible downstream: the legacy branch
 * stashes `bfc.actor_token_id` (audited as an `admin_token` actor), the
 * unified branch `bfc.actor_credential_id` (audited as an
 * `operator_integration` actor).
 *
 * The FALLBACK token is rejected here EXPLICITLY, with a distinguishable
 * 403, and BEFORE either granting branch — the invariant is absolute even
 * under a config whose fallback bytes collide with a real credential's
 * secret. The env pseudo-credential is deprecated (PRD 1.20) and never
 * operates this surface; silently treating it as unknown would send its
 * holder chasing a typo instead of the real fix.
 */
final class EnsureCredentialAdmin
{
    /**
     * The admin-equivalent ability a unified-store operator credential
     * must hold to operate the credential verbs over HTTP. The installer
     * mints its operator credential with exactly this.
     *
     * RESERVED in this ability vocabulary (Console fast-follow,
     * unimplemented): the `metadata:read` ability family —
     * least-privilege, read-audited, for future vendor-side reads of
     * `metadata`-classified endpoints (docs/http-contract.md, "Endpoint
     * classification"). No credential is issued with it and nothing
     * enforces it in this release.
     */
    public const string ABILITY = 'credential:admin';

    public function __construct(
        private readonly TokenRegistry $tokens,
        private readonly CredentialResolver $credentials,
        private readonly CredentialUsageRecorder $usage,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            $this->tokens->observeUnauthenticatedClientIdentity($request);

            abort(401);
        }

        // The deprecated fallback pseudo-credential is rejected FIRST,
        // before either granting branch, so "the fallback never operates
        // this surface" is absolute: even a config whose fallback bytes
        // collide with a real credential's secret rejects here — nothing
        // resolves, nothing stamps usage. Distinguishable, so its holder
        // chases the real fix rather than a typo.
        if ($this->isFallback($bearer)) {
            abort(403, 'Fallback tokens never operate the credential verbs. Mint an operator credential with bfc:install:operator-credential instead.');
        }

        // Branch 1 — the legacy admin token, byte-for-byte EnsureAdminToken
        // semantics (client-identity attribution included).
        $token = $this->tokens->resolveModel($bearer);

        if ($token !== null) {
            $this->tokens->recordClientIdentityFromRequest($request, $token);

            if ($token->hasScope(Scope::Admin)) {
                $request->attributes->set('bfc.actor_token_id', (string) $token->getKey());

                return $next($request);
            }

            abort(403);
        }

        // Branch 2 — a unified-store operator credential. Presenting it is
        // a use: the gated recorder both stamps it and re-asserts the row
        // still authenticates (SEC-2).
        $credential = $this->credentials->resolve(CredentialKind::Bearer, $bearer);

        if ($credential !== null) {
            if (! $this->usage->recordUsage($credential)) {
                abort(401);
            }

            if ($credential->subject_type === SubjectType::Operator && $credential->hasAbility(self::ABILITY)) {
                $request->attributes->set('bfc.actor_credential_id', $credential->id);

                return $next($request);
            }

            // A working credential without operator authority: it
            // authenticated, so this is a scope failure, not an unknown.
            abort(403);
        }

        $this->tokens->observeUnauthenticatedClientIdentity($request);

        abort(401);
    }

    /**
     * The fallback bytes themselves, compared directly — never through a
     * resolver that could touch rows or record usage.
     */
    private function isFallback(string $bearer): bool
    {
        $fallback = config('built-for-cloud.fallback_token');

        return is_string($fallback)
            && $fallback !== ''
            && hash_equals(hash('sha256', $fallback), hash('sha256', $bearer));
    }
}
