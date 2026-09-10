<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('serves the compiled standalone surface from a real route cache and still refuses takeovers', function (): void {
    $payload = sys_get_temp_dir().'/bfc-standalone-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-cache.php', 'generate', $payload]);
        $generate->mustRun();

        expect($generate->getOutput())->toContain('"contains":true');

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-cache.php', 'load', $payload]);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('standalone-route-cache-ok');
    } finally {
        @unlink($payload);
    }
});
