<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
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
            'capabilities' => ['tokens', 'ownership', 'onboarding', 'webhooks', 'credentials', 'console-keys'],
            'claimed' => $ownership !== null && $ownership->owner_token_id !== null,
        ]);
    }
}
