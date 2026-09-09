<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('keeps later host web middleware on ordinary and bearer pages', function (): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', 'late']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('late-host-web-ok');
});

it('supports one typed base or container-resolved custom starter at request dispatch', function (string $scenario): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', $scenario]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain($scenario.'-session-ok');
})->with([
    'provider boot base' => 'base',
    'provider boot custom' => 'custom',
    'later application booted base' => 'booted-base',
    'later application booted custom' => 'booted-custom',
    'post-kernel custom replacement' => 'runtime-custom',
    'post-kernel custom replacement after route cache invalidation' => 'runtime-cache-custom',
    'post-kernel custom replacement after priority mutation' => 'runtime-priority-custom',
]);

it('fails closed on invalid request-dispatch session starter counts', function (string $scenario, int $count): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-page-session-stack.php', $scenario]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())
        ->toContain('bfc.password.reset')
        ->toContain("found {$count}");
})->with([
    'later application booted zero starters' => ['booted-zero', 0],
    'later application booted duplicate starters' => ['booted-duplicate', 2],
    'post-kernel zero starters' => ['runtime-zero', 0],
    'post-kernel duplicate starters' => ['runtime-duplicate', 2],
    'globally disabled route middleware' => ['disabled', 0],
]);
