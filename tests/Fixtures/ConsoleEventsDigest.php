<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use Illuminate\Http\JsonResponse;

/**
 * A READ TRANSPORT FOR THE APP-ACTION STREAM, under a name that says
 * nothing about it — the exact route the URI-keyword pin could not see,
 * and the reason `tests/AppActionReadTransportScan.php` exists.
 *
 * Nothing about this class or the path it is mounted at contains
 * `app-action` or `audit`. It reads the stream all the same, which is
 * the only fact the scan is allowed to decide on.
 */
final class ConsoleEventsDigest
{
    public function __invoke(): JsonResponse
    {
        return new JsonResponse(AppActionEvent::query()->latest()->limit(50)->get()->toArray());
    }
}
