<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\P6ArchiveProof;
use ArtisanBuild\BuiltForCloud\Testing\P6GateCommandLedger;
use ArtisanBuild\BuiltForCloud\Testing\P6GateContract;
use ArtisanBuild\BuiltForCloud\Testing\P6GateRecorder;
use ArtisanBuild\BuiltForCloud\Testing\P6LoopbackProcess;
use ArtisanBuild\BuiltForCloud\Testing\P6PostgresRunStamp;
use ArtisanBuild\BuiltForCloud\Testing\P6RuntimeCounterProof;
use ArtisanBuild\BuiltForCloud\Testing\P6SecretLeakDetector;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6HttpClient;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6LiveCommandRunner;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6LiveSecretMaterial;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use Symfony\Component\Process\Process;

function p6SupportDirectory(): string
{
    $directory = sys_get_temp_dir().'/bfc-p6-support-'.bin2hex(random_bytes(8));
    mkdir($directory, 0700);

    return $directory;
}

it('bootstraps a fresh Laravel host without dependency installation or skeleton scripts', function (): void {
    $host = p6SupportDirectory().'/host';
    $command = P6LiveCommandRunner::freshLaravelHostCommand($host);

    expect($command)->toBe([
        'composer',
        'create-project',
        'laravel/laravel:^13.0',
        $host,
        '--no-interaction',
        '--no-install',
        '--no-scripts',
    ])->and($command)->toContain('--no-install', '--no-scripts');
});

it('installs the package archive without running scripts before fixture registration', function (): void {
    $command = P6LiveCommandRunner::archiveInstallCommand();

    expect($command)->toBe([
        'composer',
        'update',
        '--no-interaction',
        '--prefer-dist',
        '--no-scripts',
    ])->and($command)->toContain('--no-scripts')
        ->and($command)->not->toContain('--no-install');
});

it('reports only a controlled stage label when a non-sensitive command fails', function (): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/p6-live-command-failure.php']);
    $process->run();
    $arguments = [];
    $outputs = [];

    expect($process->isSuccessful())->toBeTrue($process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toBe('')
        ->and($process->getErrorOutput())->toBe("P6c live command failed at stage: fresh Laravel host creation\n")
        ->and($process->getErrorOutput())->not->toContain('child stdout', 'child stderr')
        ->and(function () use (&$arguments, &$outputs): void {
            P6LiveCommandRunner::run(
                [PHP_BINARY, '-r', 'exit(0);'],
                __DIR__,
                [],
                "unsafe\nstage",
                $arguments,
                $outputs,
            );
        })->toThrow(InvalidArgumentException::class, 'stage label is invalid');
});

it('requires observed successful commands from one exact candidate before live execution', function (): void {
    $path = p6SupportDirectory().'/commands.json';
    $sha = str_repeat('a', 40);

    foreach (array_slice(P6GateContract::COORDINATOR_COMMANDS, 0, -1) as $command) {
        P6GateCommandLedger::record($path, $sha, $command, 0);
    }

    expect(array_keys(P6GateCommandLedger::completedForLiveRunner($path, $sha)))
        ->toBe(array_slice(P6GateContract::COORDINATOR_COMMANDS, 0, -1));

    P6GateCommandLedger::record($path, $sha, 'composer test', 1);
    expect(fn () => P6GateCommandLedger::completedForLiveRunner($path, $sha))
        ->toThrow(RuntimeException::class, 'composer test');
});

it('rejects missing commands candidate drift unknown commands and declarations without probes', function (): void {
    $directory = p6SupportDirectory();
    $path = $directory.'/commands.json';
    $sha = str_repeat('b', 40);
    P6GateCommandLedger::record($path, $sha, 'composer stan', 0);

    expect(fn () => P6GateCommandLedger::completedForLiveRunner($path, $sha))
        ->toThrow(RuntimeException::class, 'composer lint:test')
        ->and(fn () => P6GateCommandLedger::completedForLiveRunner($path, str_repeat('c', 40)))
        ->toThrow(RuntimeException::class, 'different candidate');

    $recorder = new P6GateRecorder(['one', 'two']);
    $ran = false;
    $recorder->observe('one', function () use (&$ran): bool {
        $ran = true;

        return true;
    });
    expect($ran)->toBeTrue()
        ->and(fn () => $recorder->completed())->toThrow(RuntimeException::class, 'two')
        ->and(fn () => $recorder->observe('one', static fn (): bool => true))
        ->toThrow(InvalidArgumentException::class);
});

it('rejects path branch tag source and accepts one exact artifact lock entry', function (string $version, string $type): void {
    $directory = p6SupportDirectory();
    $archive = $directory.'/package.zip';
    file_put_contents($archive, 'archive');
    $sha = str_repeat('d', 40);
    $lock = ['packages' => [[
        'name' => 'artisan-build/built-for-cloud',
        'version' => $version,
        'dist' => ['type' => $type, 'url' => $archive],
    ]]];

    if ($version === '0.0.0+p6c.'.$sha && $type === 'zip') {
        expect(P6ArchiveProof::assertInstalled($lock, $sha, $archive))->toBe($version);

        return;
    }

    expect(fn () => P6ArchiveProof::assertInstalled($lock, $sha, $archive))
        ->toThrow(InvalidArgumentException::class, 'artifact archive');
})->with([
    ['dev-main', 'zip'],
    ['dev-feat/p6c', 'zip'],
    ['1.0.0', 'zip'],
    ['0.0.0+p6c.'.str_repeat('d', 40), 'path'],
    ['0.0.0+p6c.'.str_repeat('d', 40), 'zip'],
]);

it('detects a planted marker in every required secret sink', function (string $surface): void {
    $marker = 'p6-secret-marker-'.bin2hex(random_bytes(8));
    $surfaces = array_fill_keys(P6SecretLeakDetector::SURFACES, ['clean']);
    $surfaces[$surface] = ['nested' => ['value' => $marker]];

    expect(fn () => P6SecretLeakDetector::assertAbsent($surfaces, [$marker]))
        ->toThrow(RuntimeException::class, $surface);
})->with(P6SecretLeakDetector::SURFACES);

it('encodes actual signing secret bytes for the leak inventory', function (): void {
    $key = AsymmetricSecretKey::generate(new Version4);
    $material = P6LiveSecretMaterial::signingKey($key);
    $surfaces = array_fill_keys(P6SecretLeakDetector::SURFACES, ['clean']);
    $surfaces['cache_state'] = ['signing_key' => $material];

    expect($material)->toBe(bin2hex($key->raw()))
        ->and(fn () => P6SecretLeakDetector::assertAbsent($surfaces, [$material]))
        ->toThrow(RuntimeException::class, 'cache_state');
});

it('accepts only complete observed PostgreSQL lane evidence', function (string $case): void {
    $path = p6SupportDirectory().'/postgres.json';
    $stamp = [
        'schema' => 'bfc.p6.postgres.v1',
        'database_name' => 'bfc_p6_'.str_repeat('a', 32),
        'run_marker_verified' => true,
        'cases' => array_fill_keys(P6GateContract::POSTGRES_CASES, 'pass'),
        'teardown' => [
            'database_absent' => true,
            'manifest_absent' => true,
            'marker_verified' => true,
            'already_dropped' => false,
            'verdict' => 'pass',
        ],
    ];

    if ($case === 'missing-case') {
        unset($stamp['cases']['replay']);
    } elseif ($case === 'unverified-marker') {
        $stamp['run_marker_verified'] = false;
    } elseif ($case === 'incomplete-teardown') {
        $stamp['teardown']['database_absent'] = false;
    }

    file_put_contents($path, json_encode($stamp, JSON_THROW_ON_ERROR));

    if ($case === 'complete') {
        expect(P6PostgresRunStamp::read($path)['database_name'])->toBe($stamp['database_name']);

        return;
    }

    expect(fn () => P6PostgresRunStamp::read($path))
        ->toThrow(RuntimeException::class, 'PostgreSQL stamp');
})->with(['complete', 'missing-case', 'unverified-marker', 'incomplete-teardown']);

it('requires exact shared runtime counter deltas', function (): void {
    P6RuntimeCounterProof::assertDeltas(
        ['mcp_on_a' => 4, 'mcp_on_b' => 2],
        ['mcp_on_a' => 5, 'mcp_on_b' => 3],
        ['mcp_on_a' => 1, 'mcp_on_b' => 1],
    );

    expect(fn () => P6RuntimeCounterProof::assertDeltas(
        ['mcp_on_a' => 4],
        ['mcp_on_a' => 6],
        ['mcp_on_a' => 1],
    ))->toThrow(RuntimeException::class, 'did not advance exactly');
});

it('classifies only the HTTP transitions used by cross-node counter proofs', function (string $method, string $path, ?string $counter): void {
    expect(P6RuntimeCounterProof::counterForRequest($method, $path))->toBe($counter);
})->with([
    ['POST', '_bfc-p6c/mcp', 'mcp'],
    ['POST', 'bfc/credentials/test-id/rotate', 'credential_rotate'],
    ['DELETE', 'bfc/credentials/test-id', 'credential_revoke'],
    ['POST', 'bfc/login', 'session_establish'],
    ['GET', '_bfc-p6c/session', 'session_accept'],
    ['POST', '_bfc-p6c/session/invalidate', 'session_invalidate'],
    ['POST', '_bfc-p6c/managed-refresh/test-user', 'managed_refresh'],
    ['GET', 'bfc/meta', null],
]);

it('identity checks and boundedly tears down a real loopback helper', function (): void {
    $root = dirname(__DIR__);
    $listener = P6LoopbackProcess::start(
        [PHP_BINARY, '-S', '127.0.0.1:{port}', __DIR__.'/Fixtures/p6-loopback.php'],
        $root,
        [],
        static function (int $port): bool {
            $socket = @stream_socket_client('tcp://127.0.0.1:'.$port, $errorNumber, $error, 0.1);
            if (! is_resource($socket)) {
                return false;
            }

            fclose($socket);

            return true;
        },
    );

    $identity = $listener->identity();
    $client = new P6HttpClient;
    $duplicate = $client->request($listener->port, 'GET', '/duplicate', [
        ['X-BfC-Duplicate', 'one'],
        ['X-BfC-Duplicate', 'two'],
    ]);
    $client->request($listener->port, 'GET', '/set-cookie');
    $cookies = p6LiveRunnerSupportJson($client->request($listener->port, 'GET', '/cookies')['body']);
    $client->request($listener->port, 'GET', '/clear-cookie');

    expect($identity['port'])->toBe($listener->port)
        ->and($identity['identity_verified'])->toBeTrue()
        ->and($duplicate['status'])->toBe(207)
        ->and(p6LiveRunnerSupportJson($duplicate['body'])['duplicate'])->toContain('one', 'two')
        ->and($cookies['cookie'])->toContain('p6_one=first', 'p6_two=second')
        ->and($client->cookies())->not->toHaveKey('p6_one')
        ->and($client->cookies())->toHaveKey('p6_two', 'second')
        ->and($listener->stop())->toBeTrue();
});

/** @return array<string, mixed> */
function p6LiveRunnerSupportJson(string $json): array
{
    $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

    return is_array($decoded) ? $decoded : throw new RuntimeException('Expected fixture JSON.');
}
