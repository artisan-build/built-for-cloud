<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('keeps later host web middleware on ordinary and bearer pages', function (): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', 'late']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('late-host-web-ok');
});

it('supports one base or container-resolved custom session starter', function (string $shape): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', $shape]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain($shape.'-session-ok');
})->with(['base', 'custom']);

it('fails closed on invalid final session starter counts', function (string $shape, int $count): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', $shape]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())
        ->toContain('bfc.password.reset')
        ->toContain("found {$count}");
})->with([
    'zero session starters' => ['zero', 0],
    'duplicate session starters' => ['duplicate', 2],
]);
