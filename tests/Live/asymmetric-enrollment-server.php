<?php

declare(strict_types=1);

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));

$barrierDirectory = getenv('BFC_HARNESS_CONCURRENT_BARRIER');
$barrier = $_SERVER['HTTP_X_BFC_HARNESS_CONCURRENT_EXCHANGE'] ?? null;
$worker = $_SERVER['HTTP_X_BFC_HARNESS_CONCURRENT_WORKER'] ?? null;

if (is_string($barrierDirectory)
    && is_string($barrier)
    && preg_match('/\A[0-9a-f]{32}\z/D', $barrier) === 1
    && in_array($worker, ['1', '2'], true)
    && parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) === '/bfc/device/token') {
    touch("{$barrierDirectory}/{$barrier}-{$worker}.ready");
    $deadline = hrtime(true) + 10_000_000_000;

    while ((! is_file("{$barrierDirectory}/{$barrier}-1.ready")
        || ! is_file("{$barrierDirectory}/{$barrier}-2.ready"))
        && hrtime(true) < $deadline) {
        usleep(10_000);
    }

    if (! is_file("{$barrierDirectory}/{$barrier}-1.ready")
        || ! is_file("{$barrierDirectory}/{$barrier}-2.ready")) {
        throw new RuntimeException('The concurrent HTTP exchange barrier timed out.');
    }
}

require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/public/index.php';
