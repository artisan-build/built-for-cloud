<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Http\JsonResponse;

/**
 * The same read transport reached one class further away: this
 * controller names no model at all, and the class it delegates to is
 * where the stream is read.
 *
 * It is here for both halves of that. A direct-reference check passes
 * it, and the transitive walk catches it — but only when the class it
 * delegates to is one the walk can resolve. {@see ConsoleEventsSource}
 * is a test fixture and not a package class, so the router-level scan
 * reports this route as unrelated and the one-hop follow is driven over
 * an explicit class map instead. Both facts are asserted in
 * `tests/AppActionAuditTest.php`, because the second is the walk's
 * bound and a fixture that only demonstrated the happy half would hide
 * it.
 */
final class ConsoleEventsReport
{
    public function __invoke(ConsoleEventsSource $source): JsonResponse
    {
        return new JsonResponse($source->recent());
    }
}
