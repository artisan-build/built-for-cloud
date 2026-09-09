<?php

declare(strict_types=1);
use Symfony\Component\Process\Process;

it('excludes base and custom session starters across late route mutations', function (string $scenario): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/bearer-handoff-route-exclusion.php', $scenario]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain($scenario.'-exclusion-ok');
})->with([
    'later provider base route attachment' => 'provider-base',
    'later provider custom route attachment' => 'provider-custom',
    'later application booted base route attachment' => 'booted-base',
    'later application booted custom route attachment' => 'booted-custom',
    'post-kernel base route attachment' => 'post-kernel-base',
    'post-kernel custom route attachment' => 'post-kernel-custom',
    'late RouteMatched base route attachment' => 'matched-base',
    'late RouteMatched custom route attachment' => 'matched-custom',
    'late base middleware group attachment' => 'group-base',
    'late custom middleware group attachment' => 'group-custom',
    'cached base route stack' => 'cached-base',
    'cached custom route stack' => 'cached-custom',
]);
