<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\P6GateCommandLedger;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

$root = dirname(__DIR__, 2);
$label = $argv[1] ?? '';
$command = array_slice($argv, 2);

if ($label === '' || $command === []) {
    fwrite(STDERR, "usage: php tests/Support/run-p6-gate-command.php <label> <command> [arguments...]\n");
    exit(2);
}

$shaProcess = new Process(['git', 'rev-parse', 'HEAD'], $root);
if ($shaProcess->run() !== 0 || preg_match('/^[a-f0-9]{40}$/D', $sha = trim($shaProcess->getOutput())) !== 1) {
    fwrite(STDERR, "Could not resolve the P6c candidate SHA.\n");
    exit(1);
}

$process = new Process($command, $root, ['BFC_P6_CANDIDATE_SHA' => $sha], null, null);
$exitCode = $process->run(static function (string $type, string $output): void {
    fwrite($type === Process::ERR ? STDERR : STDOUT, $output);
});
$ledger = getenv('BFC_P6_COMMAND_STAMP');

if (is_string($ledger) && $ledger !== '') {
    try {
        P6GateCommandLedger::record($ledger, $sha, $label, $exitCode);
    } catch (Throwable $exception) {
        fwrite(STDERR, "Could not record the P6c command result: {$exception->getMessage()}\n");
        exit(1);
    }
}

exit($exitCode);
