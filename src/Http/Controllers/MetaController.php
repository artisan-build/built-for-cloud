<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
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
            // guard, the door and the actor table have all since
            // shipped and each is advertised below under its own name.
            // This one is unconditional; those are not.
            //
            // `console-vitals` is likewise named for what it serves —
            // the ops-vitals READ (Console PRD D9), one
            // `metadata`-classified endpoint behind `metadata:read`.
            // Not `console`, and not `dashboard`: the dashboard is the
            // vendor's, this is the one surface it reads.
            //
            // `console-guard` is named for what THIS release serves: the
            // delegated-session guard, the shadow-actor table and the
            // re-entry 401 — the machinery an entered operator's session
            // runs on. Still not `console`, and deliberately not
            // `console-enter`: the door has its own capability below
            // under a STRICTER predicate, so a control plane that read
            // this one as "you can hand an operator to this deployment"
            // would be reading a promise this one does not make — an app
            // that defined its own `bfc-console` guard reports this and
            // not `console-enter`. It appears only when the deployment has
            // actually enabled the Console, because with the flag off
            // none of that machinery is registered and advertising it
            // would be a lie about this deployment rather than about
            // the package.
            //
            // `console-enter` is the one that finally says a delegated
            // operator can be handed to this deployment: `POST
            // /bfc/console/enter` is mounted and will redeem a signed
            // assertion. Its condition is STRICTER than
            // `console-guard`'s — it also requires that the reserved
            // guard name resolves to this package's own driver, which
            // is exactly the condition the route is mounted under, so
            // the capability and the route can never disagree. An app
            // that defined its own `bfc-console` guard has the guard
            // machinery and does NOT get the package's door.
            //
            // `console-chrome-assets` is named for the two things this
            // deployment SERVES: the `bfc::layout` view namespace and
            // the re-entry interceptor at
            // `GET /bfc/console/chrome.js`. Not `console-chrome`, and
            // the difference is the whole of the name — whether any
            // PAGE in this app actually wears the chrome is the
            // application's own decision, made by whichever of its
            // templates extends `bfc::layout`, and no package
            // capability can see that or promise it. A control plane
            // reading `console-chrome` as "an operator handed here will
            // see whose session they are in" would be reading a promise
            // this package cannot keep; `console-chrome-assets` says
            // only that the machinery is served, which is exactly what
            // is true. Its condition is the one the chrome route is
            // mounted under, so the capability and the route can never
            // disagree.
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
            // It is UNCONDITIONAL, unlike the three predicated ones
            // above it, because what
            // it describes is schema and an emission point that every
            // install carries whether or not the Console is enabled —
            // the same standing `credentials` has. The DOOR's own
            // emission is already conditional and already advertised:
            // that is what `console-enter` says, and duplicating its
            // predicate here would give a control plane two names for
            // one fact.
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
            // check can see, exactly as `console-chrome-assets` cannot
            // see whether any page wears the chrome.
            'capabilities' => self::capabilities(),
            'claimed' => $ownership !== null && $ownership->owner_token_id !== null,
        ];

        if (($mcp = McpConfiguration::endpoint()) !== null) {
            $payload['endpoints'] = ['mcp' => $mcp];
        }

        return response()->json($payload);
    }

    /**
     * Additive per the compatibility rule (docs/http-contract.md):
     * consumers feature-detect on membership, never on position.
     *
     * @return list<string>
     */
    private static function capabilities(): array
    {
        $capabilities = [
            'tokens', 'ownership', 'onboarding', 'webhooks', 'credentials',
            'console-keys', 'console-key-retire', 'console-vitals', 'app-action-audit-emit',
        ];

        if (ConsoleGuardConfiguration::enabled()) {
            $capabilities[] = 'console-guard';
        }

        if (ConsoleGuardConfiguration::servesDelegatedEntry()) {
            $capabilities[] = 'console-enter';
            $capabilities[] = 'console-chrome-assets';
        }

        if (McpConfiguration::serves()) {
            $capabilities[] = 'mcp-serve';
        }

        if (McpConfiguration::delegated()) {
            $capabilities[] = 'mcp-delegated';
        }

        return $capabilities;
    }
}
