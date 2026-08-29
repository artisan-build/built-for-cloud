<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;

/**
 * A read transport that names no model: it queries the table directly,
 * by its literal name, which is why the table names are in
 * `AppActionReadTransportScan::STREAM` alongside the two models.
 */
final class ConsoleEventsTally
{
    public function __invoke(): JsonResponse
    {
        return new JsonResponse(['count' => DB::table('bfc_app_action_events')->count()]);
    }
}
