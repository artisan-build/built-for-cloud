<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Mcp\McpConfiguration;
use ArtisanBuild\BuiltForCloud\Ownership;
use Illuminate\Http\JsonResponse;

final class MetaController
{
    public function __invoke(): JsonResponse
    {
        $ownership = Ownership::current();

        $payload = [
            'product' => config('built-for-cloud.product'),
            'bfc_version' => BuiltForCloud::VERSION,
            'api_version' => BuiltForCloud::API_VERSION,
            // Additive per the compatibility rule (docs/http-contract.md):
            // consumers feature-detect on membership, never on position.
            //
            // `console-keys` is deliberately NOT `console`: what it
            // names is countersigning-key custody (the claim-time
            // exchange and the re-key verb, Console PRD D12), not the
            // Console itself. A control plane that read `console` as
            // "this deployment can be entered" would be reading a
            // promise this capability does not make — and would now be
            // reading it wrongly rather than merely early, since the
            // door was retired in v0.17.0 while this capability and the
            // keyring it names remain. This one is unconditional.
            //
            // `console-vitals` is likewise named for what it serves —
            // the ops-vitals READ (Console PRD D9), one
            // `metadata`-classified endpoint behind `metadata:read`.
            // Not `console`, and not `dashboard`: the dashboard is the
            // vendor's, this is the one surface it reads.
            //
            // `console-key-retire` says this deployment serves the
            // RETIREMENT verb, `POST /bfc/console/keys/{key_id}/retire`
            // — and it is a name of its own rather than a widening of
            // `console-keys` because widening it would say nothing a
            // control plane can act on. `console-keys` is already
            // reported by every deployment that serves the delivery
            // surfaces, including releases where retirement was
            // reachable only from PHP inside the app, so a control plane
            // reading it cannot tell whether the verb it wants to call
            // exists. This one can only be read as "the retire verb is
            // here". The verb is in the name for the same reason it is
            // in `app-action-audit-emit`: it says what this deployment
            // will DO, not what it holds.
            //
            // `app-action-audit-emit` says this deployment RECORDS
            // app-action audit events (Console PRD D17): the
            // `bfc_app_action_events` table, its outbox, and the
            // emission point an app calls. The verb is in the name on
            // purpose — there is NO read transport for this stream in
            // this release, and `app-action-audit` on its own is exactly
            // the name a control plane would read as "I can query this".
            // It is UNCONDITIONAL because what it describes is schema
            // and an emission point that every install carries —
            // the same standing `credentials` has.
            //
            // `mcp-serve` says this deployment DECLARES that it serves
            // an MCP endpoint at the advertised path: the same
            // `built-for-cloud.mcp.path` predicate that adds
            // `endpoints.mcp`, so the capability and the path it names
            // cannot disagree. The package ships no MCP server and
            // mounts no route — the declaration is the deployment
            // naming the path IT mounted, which is why this is a
            // declaration-predicated capability rather than an
            // unconditional one like `tokens`.
            //
            // `mcp-delegated` says this deployment's advertised MCP
            // endpoint accepts a delegated console assertion. Strictly
            // stronger than `mcp-serve`, and its two halves are held
            // differently because only one is observable from inside
            // the package: the router must confirm that the route it
            // would dispatch for the MCP POST at the declared path —
            // matched by verb and domain, middleware gathered the way
            // the pipeline runs it — carries `AuthenticateMcp`, so an
            // advertised capability is truly guarded (a guarded decoy
            // verb, another deployment's domain, or an excluded guard
            // cannot earn it; a differently-hosted domain-qualified
            // route understates, never overstates). The other half —
            // that the product's own suite runs the delegated-tool
            // conformance assertion — is a declaration no package
            // check can see.
            'capabilities' => self::capabilities(),
            'claimed' => $ownership !== null && $ownership->hasOwner(),
        ];

        if (($mcp = McpConfiguration::endpoint()) !== null) {
            $payload['endpoints'] = ['mcp' => $mcp];
        }

        return response()->json($payload);
    }

    /**
     * Additive per the compatibility rule (docs/http-contract.md):
     * consumers feature-detect on membership, never on position.
     * `tokens` is a historical family name kept for wire stability; it now
     * names credentials served solely by the unified store.
     *
     * @return list<string>
     */
    private static function capabilities(): array
    {
        $capabilities = [
            'tokens', 'ownership', 'onboarding', 'webhooks', 'credentials',
            'console-keys', 'console-key-retire', 'console-vitals', 'app-action-audit-emit',
            'managed-enrolment',
        ];

        if (McpConfiguration::serves()) {
            $capabilities[] = 'mcp-serve';
        }

        if (McpConfiguration::delegated()) {
            $capabilities[] = 'mcp-delegated';
        }

        return $capabilities;
    }
}
