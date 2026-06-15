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

it('resolves the cloud application id from dot cloud config when config is null', function (): void {
    config(['built-for-cloud.cloud.application' => null]);

    $directory = base_path('.cloud');
    $path = $directory.'/config.json';
    $existing = is_file($path) ? (string) file_get_contents($path) : null;
    $createdDirectory = false;

    if (! is_dir($directory)) {
        mkdir($directory);
        $createdDirectory = true;
    }

    file_put_contents($path, '{"application_id":"app-x"}');

    Process::fake([
        '*' => Process::result('[{"id":"env-x","name":"Production"}]'),
    ]);

    try {
        expect((new CloudCommandRunner)->resolveEnvironment())->toBe('env-x');

        Process::assertRan(function ($process): bool {
            return $process->command === [
                'cloud',
                'environment:list',
                'app-x',
                '--json',
                '--fields=id,name',
            ];
        });
    } finally {
        if ($existing === null) {
            unlink($path);

            if ($createdDirectory) {
                rmdir($directory);
            }
        } else {
            file_put_contents($path, $existing);
        }
    }
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

it('throws when a cloud environment lacks a valid id', function (): void {
    config(['built-for-cloud.cloud.application' => 'app-invalid']);

    Process::fake([
        '*' => Process::result('[{"name":"Production"}]'),
    ]);

    (new CloudCommandRunner)->resolveEnvironment();
})->throws(RuntimeException::class, 'environment without a valid id');

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

it('throws when cloud command output has no valid exit code', function (): void {
    Process::fake([
        '*' => Process::result('{"output":"remote output"}'),
    ]);

    (new CloudCommandRunner)->run('env-1', 'token:create app --execute --hash='.hash('sha256', 'secret'));
})->throws(RuntimeException::class, 'without a valid exit code');
