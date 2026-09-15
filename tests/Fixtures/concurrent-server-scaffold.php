<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Install\ServerScaffold;

require __DIR__.'/../../vendor/autoload.php';

$environmentPath = $argv[1] ?? '';
$composerPath = $argv[2] ?? '';
$ready = $argv[3] ?? '';
$go = $argv[4] ?? '';
$attempting = $argv[5] ?? '';
$worker = $argv[6] ?? '';

$inputs = [
    'one' => [['WORKER_ONE' => 'first'], ['worker/one' => '^1']],
    'two' => [['WORKER_TWO' => 'second'], ['worker/two' => '^2']],
];

if (! isset($inputs[$worker])) {
    fwrite(STDERR, "Invalid concurrent scaffold worker.\n");
    exit(2);
}

try {
    $readyPipe = fopen($ready, 'wb');
    if ($readyPipe === false || fwrite($readyPipe, '1') !== 1) {
        throw new RuntimeException('Could not signal scaffold readiness.');
    }
    fclose($readyPipe);

    $goPipe = fopen($go, 'rb');
    if ($goPipe === false || fread($goPipe, 1) !== '1') {
        throw new RuntimeException('Could not cross the scaffold release barrier.');
    }
    fclose($goPipe);

    $attemptingPipe = fopen($attempting, 'wb');
    if ($attemptingPipe === false || fwrite($attemptingPipe, '1') !== 1) {
        throw new RuntimeException('Could not signal the scaffold attempt.');
    }
    fclose($attemptingPipe);

    [$environment, $requirements] = $inputs[$worker];
    $result = (new ServerScaffold)->install($environmentPath, $composerPath, $environment, $requirements);

    fwrite(STDOUT, json_encode($result->stages(), JSON_THROW_ON_ERROR));
    exit(0);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage());
    exit(1);
}
