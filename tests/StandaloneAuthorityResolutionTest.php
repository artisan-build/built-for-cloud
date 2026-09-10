<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('refuses authority stripped through alias, group and exclusion resolution', function (string $vector): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-authority-resolution.php', $vector]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain("standalone-authority-resolution-{$vector}-refused");
})->with(['control', 'fqcn-alias', 'fqcn-group', 'alias-exclusion', 'fqcn-exclusion', 'exclusion-alias']);
