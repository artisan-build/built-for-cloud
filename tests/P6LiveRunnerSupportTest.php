<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\P6ArchiveProof;
use ArtisanBuild\BuiltForCloud\Testing\P6GateCommandLedger;
use ArtisanBuild\BuiltForCloud\Testing\P6GateContract;
use ArtisanBuild\BuiltForCloud\Testing\P6GateRecorder;
use ArtisanBuild\BuiltForCloud\Testing\P6LoopbackProcess;
use ArtisanBuild\BuiltForCloud\Testing\P6SecretLeakDetector;

function p6SupportDirectory(): string
{
    $directory = sys_get_temp_dir().'/bfc-p6-support-'.bin2hex(random_bytes(8));
    mkdir($directory, 0700);

    return $directory;
}

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

it('identity checks and boundedly tears down a real loopback helper', function (): void {
    $root = dirname(__DIR__);
    $listener = P6LoopbackProcess::start(
        [PHP_BINARY, '-S', '127.0.0.1:{port}', $root.'/Fixtures/p6-loopback.php'],
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
    expect($identity['port'])->toBe($listener->port)
        ->and($identity['identity_verified'])->toBeTrue()
        ->and($listener->stop())->toBeTrue();
});
