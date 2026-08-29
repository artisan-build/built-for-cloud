<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Ownership;
use Illuminate\Http\JsonResponse;

final class MetaController
{
    public function __invoke(): JsonResponse
    {
        $ownership = Ownership::current();

        return response()->json([
            'product' => config('built-for-cloud.product'),
            'bfc_version' => BuiltForCloud::VERSION,
            'api_version' => BuiltForCloud::API_VERSION,
            // Additive per the compatibility rule (docs/http-contract.md):
            // consumers feature-detect on membership, never on position.
            //
            // `console-keys` is deliberately NOT `console`: what this
            // release serves is countersigning-key custody (the
            // claim-time exchange and the re-key verb, Console PRD D12),
            // not the Console itself — no delegated guard, no enter
            // endpoint, no delegated-actor table. A control plane that
            // read `console` as "this deployment can be entered" would
            // be reading a promise nothing here keeps.
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
            // `console-enter`: there is no enter endpoint yet, so a
            // control plane that read this as "you can hand an operator
            // to this deployment" would be reading a promise nothing
            // here keeps. It appears only when the deployment has
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
            // `app-action-audit-emit` says this deployment RECORDS
            // app-action audit events (Console PRD D17): the
            // `bfc_app_action_events` table, its outbox, and the
            // emission point an app calls. The verb is in the name on
            // purpose — there is NO read transport for this stream in
            // this release, and `app-action-audit` on its own is exactly
            // the name a control plane would read as "I can query this".
            // It is UNCONDITIONAL, unlike the two above it, because what
            // it describes is schema and an emission point that every
            // install carries whether or not the Console is enabled —
            // the same standing `credentials` has. The DOOR's own
            // emission is already conditional and already advertised:
            // that is what `console-enter` says, and duplicating its
            // predicate here would give a control plane two names for
            // one fact.
            'capabilities' => self::capabilities(),
            'claimed' => $ownership !== null && $ownership->owner_token_id !== null,
        ]);
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
            'console-keys', 'console-vitals', 'app-action-audit-emit',
        ];

        if (ConsoleGuardConfiguration::enabled()) {
            $capabilities[] = 'console-guard';
        }

        if (ConsoleGuardConfiguration::servesDelegatedEntry()) {
            $capabilities[] = 'console-enter';
        }

        return $capabilities;
    }
}
