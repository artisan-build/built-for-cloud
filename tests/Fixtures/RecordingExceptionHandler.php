<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Throwable;

/**
 * Records what the package hands to the application's exception handler,
 * so a test can assert that a SWALLOWED failure was nonetheless made
 * visible rather than silently dropped.
 */
final class RecordingExceptionHandler implements ExceptionHandler
{
    /** @var list<Throwable> */
    public static array $reported = [];

    public static function reset(): void
    {
        self::$reported = [];
    }

    public function report(Throwable $e): void
    {
        self::$reported[] = $e;
    }

    public function shouldReport(Throwable $e): bool
    {
        return true;
    }

    public function render($request, Throwable $e): mixed
    {
        throw $e;
    }

    public function renderForConsole($output, Throwable $e): void
    {
        // Nothing to render in a test.
    }
}
