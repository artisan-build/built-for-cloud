<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\Support\P6LiveCommandRunner;

require dirname(__DIR__, 2).'/vendor/autoload.php';

$arguments = [];
$outputs = [];

try {
    P6LiveCommandRunner::run(
        [PHP_BINARY, '-r', 'fwrite(STDOUT, "child stdout"); fwrite(STDERR, "child stderr"); exit(9);'],
        dirname(__DIR__, 2),
        [],
        'fresh Laravel host creation',
        $arguments,
        $outputs,
    );
} catch (RuntimeException $exception) {
    exit($exception->getMessage() === 'fresh Laravel host creation exited non-zero.' ? 0 : 2);
}

exit(3);
