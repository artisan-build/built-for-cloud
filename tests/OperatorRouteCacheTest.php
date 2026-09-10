<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('refuses operator gate resolution attacks from a real compiled route collection', function (): void {
    $payload = sys_get_temp_dir().'/bfc-operator-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/operator-route-cache.php', 'generate', $payload]);
        $generate->mustRun();

        expect($generate->getOutput())->toContain('"contains":true');

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/operator-route-cache.php', 'load', $payload]);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('operator-route-cache-ok');
    } finally {
        @unlink($payload);
    }
});
