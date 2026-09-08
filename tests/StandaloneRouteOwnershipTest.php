<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('fails thin-host boot on reserved standalone name-only and method-path collisions', function (string $collision): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-collision.php', $collision]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and($process->getOutput())->toContain('reserved by built-for-cloud standalone authentication');
})->with(['name', 'pair']);
