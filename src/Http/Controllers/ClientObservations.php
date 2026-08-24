<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\ClientIdentityObservation;
use Illuminate\Http\JsonResponse;

final class ClientObservations
{
    private const NOTE = 'These identities were claimed on requests that presented no valid credential; a claimed identity is unauthenticated, trivially spoofable, and proves nothing.';

    public function __invoke(): JsonResponse
    {
        $enabled = (bool) config('built-for-cloud.client_identity.observe_unauthenticated', false);
        $max = (int) config('built-for-cloud.client_identity.max_observations', 100);

        $observations = $enabled
            ? ClientIdentityObservation::query()
                ->orderByDesc('last_seen_at')
                ->get(['client_identity', 'first_seen_at', 'last_seen_at', 'observation_count'])
                ->map(static fn (ClientIdentityObservation $observation): array => [
                    'client_identity' => $observation->client_identity,
                    'first_seen_at' => $observation->first_seen_at,
                    'last_seen_at' => $observation->last_seen_at,
                    'observation_count' => $observation->observation_count,
                ])
                ->values()
                ->all()
            : [];

        return response()->json([
            // A control plane must be able to tell "off" from "on and nothing seen".
            'enabled' => $enabled,
            // Carried in the payload, not just the docs: nobody should have to have read them.
            'advisory' => true,
            'spoofable' => true,
            'note' => self::NOTE,
            // Silent truncation reads as complete data, so say when new identities are dropped.
            'at_capacity' => ClientIdentityObservation::query()->count() >= $max,
            'max_observations' => $max,
            'observations' => $observations,
        ]);
    }
}
