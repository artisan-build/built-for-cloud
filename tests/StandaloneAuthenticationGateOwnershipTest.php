<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('refuses standalone authentication gate resolution attacks at boot', function (string $vector): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth.php', $vector, 'boot']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('standalone-auth-gate-boot-refused');
})->with([
    'FQCN alias' => 'fqcn-alias',
    'FQCN group' => 'fqcn-group',
    'FQCN exclusion' => 'fqcn-exclusion',
    'package alias exclusion' => 'alias-exclusion',
]);

it('refuses every standalone authentication route before effects or disclosure after boot', function (string $vector): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth.php', $vector, 'match']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('standalone-auth-gate-match-refused-11');
})->with([
    'FQCN alias' => 'fqcn-alias',
    'FQCN group' => 'fqcn-group',
    'FQCN exclusion' => 'fqcn-exclusion',
    'package alias exclusion' => 'alias-exclusion',
]);

it('refuses every standalone authentication route from a real compiled route collection', function (): void {
    $payload = sys_get_temp_dir().'/bfc-standalone-auth-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-cache.php', 'generate', $payload]);
        $generate->mustRun();

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth-route-cache.php', $payload]);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('standalone-auth-route-cache-refused-11');
    } finally {
        @unlink($payload);
    }
});
