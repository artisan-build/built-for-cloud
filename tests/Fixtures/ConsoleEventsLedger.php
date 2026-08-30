<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use artisanbuild\builtforcloud\audit\appactionevent;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;

/**
 * A read transport spelled in a case the first revision of the scan did
 * not match. PHP resolves class names case-insensitively, so
 * `appactionevent` IS the model and this controller runs; the matcher
 * compared case-sensitively and reported it as reaching nothing.
 *
 * The import is pint's — it moved the fully-qualified spelling up here
 * and kept the case, which is the part that matters. The table name is
 * folded too, for the parallel reason: which identifier case a database
 * folds is the database's business, not something to decide in a scan.
 */
final class ConsoleEventsLedger
{
    public function __invoke(): JsonResponse
    {
        $rows = appactionevent::query()->limit(5)->get();

        return new JsonResponse([
            'rows' => $rows->all(),
            'ledger' => DB::table('BFC_APP_ACTION_OUTBOX')->count(),
        ]);
    }
}
