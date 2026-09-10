<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('keeps package authority and authentication gates effective through same-name host collisions', function (): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-middleware-collision.php']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('standalone-middleware-collision-refused');
});
