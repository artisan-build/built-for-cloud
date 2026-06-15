<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use Illuminate\Support\Facades\Process;

it('resolves a single cloud environment without prompting', function (): void {
    config(['built-for-cloud.cloud.application' => 'app-1']);

    Process::fake([
        '*' => Process::result('[{"id":"env-1","name":"Production"}]'),
    ]);

    expect((new CloudCommandRunner)->resolveEnvironment())->toBe('env-1');
});

it('short-circuits explicit environment resolution without a process call', function (): void {
    Process::fake();

    expect((new CloudCommandRunner)->resolveEnvironment('env-x'))->toBe('env-x');

    Process::assertNothingRan();
});

it('throws when no cloud environments are found', function (): void {
    config(['built-for-cloud.cloud.application' => 'app-empty']);

    Process::fake([
        '*' => Process::result('[]'),
    ]);

    (new CloudCommandRunner)->resolveEnvironment();
})->throws(RuntimeException::class, 'No environments found');

it('runs artisan commands through the cloud cli and parses json output', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"remote output","exitCode":7}'),
    ]);

    $result = (new CloudCommandRunner)->run('env-1', 'token:list --execute --json');

    expect($result)->toBe([
        'output' => 'remote output',
        'exitCode' => 7,
    ]);

    Process::assertRan(function ($process): bool {
        return $process->command === [
            'cloud',
            'command:run',
            'env-1',
            '--cmd',
            'php artisan token:list --execute --json',
            '--json',
            '--fields=output,exitCode',
            '--no-interaction',
        ];
    });
});
