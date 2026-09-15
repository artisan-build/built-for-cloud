<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Install\InstallTargetState;
use ArtisanBuild\BuiltForCloud\Install\ServerScaffold;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\InstallFixtureCommand;
use Composer\Semver\VersionParser;
use Dotenv\Dotenv;
use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class);

final class InstallScaffoldHarness
{
    use WritesInstallEnv;
}

final class FailingInstallMintCommand extends Command
{
    protected $signature = 'bfc:install:operator-credential {--force}';

    public function handle(): int
    {
        return self::FAILURE;
    }
}

function install_scaffold_temp_dir(): string
{
    $path = sys_get_temp_dir().'/bfc-install-'.bin2hex(random_bytes(6));

    mkdir($path);

    return $path;
}

/** @return array<string, array{contents: string, mode: int}> */
function install_scaffold_snapshot(string $root): array
{
    $snapshot = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file instanceof SplFileInfo && $file->isFile()) {
            $snapshot[substr($file->getPathname(), strlen($root) + 1)] = [
                'contents' => (string) file_get_contents($file->getPathname()),
                'mode' => fileperms($file->getPathname()) & 0777,
            ];
        }
    }
    ksort($snapshot);

    return $snapshot;
}

it('sets new and existing environment values without disturbing unrelated lines', function (): void {
    $harness = new InstallScaffoldHarness;
    $contents = "APP_NAME=Testing\nEXISTING=old\n# Comment\n";

    $updated = $harness->setEnvironmentValue($contents, 'NEW_KEY', 'plain');
    $updated = $harness->setEnvironmentValue($updated, 'EXISTING', 'new value');

    expect($updated)->toContain("APP_NAME=Testing\n")
        ->and($updated)->toContain("# Comment\n")
        ->and($updated)->toContain("NEW_KEY=plain\n")
        ->and($updated)->toContain("EXISTING=\"new value\"\n")
        ->and(substr_count($updated, 'EXISTING='))->toBe(1);
});

it('does not replace env keys with matching prefixes', function (): void {
    $harness = new InstallScaffoldHarness;

    $updated = $harness->setEnvironmentValue("TOKEN_SUFFIX=keepme\n", 'TOKEN', 'new');

    expect($updated)->toContain("TOKEN_SUFFIX=keepme\n")
        ->and($updated)->toContain("TOKEN=new\n")
        ->and(substr_count($updated, 'TOKEN_SUFFIX='))->toBe(1)
        ->and(substr_count($updated, 'TOKEN='))->toBe(1);
});

it('escapes newlines and quotes in env values to prevent injected variables', function (): void {
    $harness = new InstallScaffoldHarness;

    $updated = $harness->setEnvironmentValue('', 'SECRET', "a\nINJECTED=yes \"quoted\"");

    expect($updated)->toBe("SECRET=\"a\\nINJECTED=yes \\\"quoted\\\"\"\n")
        ->and(substr_count($updated, 'SECRET='))->toBe(1)
        ->and(substr_count($updated, "\nINJECTED="))->toBe(0);
});

it('round trips every supported environment value literally and reruns without writing', function (): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($env, "APP_NAME=interpolation-source\nEXISTING=old-sensitive-value\nKEEP=unchanged\n");
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");
    $values = [
        'BACKSLASH' => 'path\\segment\\',
        'CARRIAGE_RETURN' => "left\rright",
        'COMBINED' => '='.'"'.'${APP_NAME}'."\\\n\r".'$0'.'${1}',
        'DOLLAR_ZERO' => '$0',
        'EMPTY_VALUE' => '',
        'EQUALS' => 'left=right',
        'EXISTING' => 'replacement-$0-${1}',
        'INTERPOLATION' => '${APP_NAME}',
        'NEWLINE' => "left\nright",
        'NUMERIC_BRACES' => '${1}',
        'QUOTE' => 'say "hello"',
    ];
    $service = new ServerScaffold;

    $first = $service->install($env, $composer, $values, ['vendor/package' => '^1']);
    $firstBytes = (string) file_get_contents($env);
    $firstInode = fileinode($env);
    $loaded = Dotenv::createArrayBacked($dir)->load();
    touch($env, 946684800);

    $second = $service->install($env, $composer, $values, ['vendor/package' => '^1']);

    expect($first->stages())->toBe(['environment' => 'replaced', 'composer' => 'replaced'])
        ->and($second->stages())->toBe(['environment' => 'unchanged', 'composer' => 'unchanged'])
        ->and((string) file_get_contents($env))->toBe($firstBytes)
        ->and(fileinode($env))->toBe($firstInode)
        ->and(filemtime($env))->toBe(946684800)
        ->and($loaded['APP_NAME'])->toBe('interpolation-source')
        ->and($loaded['KEEP'])->toBe('unchanged');

    foreach ($values as $key => $value) {
        expect($loaded[$key] ?? null)->toBe($value);
    }
});

it('quotes empty env values idempotently', function (): void {
    $harness = new InstallScaffoldHarness;

    $updated = $harness->setEnvironmentValue('', 'EMPTY_KEY', '');
    $secondWrite = $harness->setEnvironmentValue($updated, 'EMPTY_KEY', '');

    expect($updated)->toBe("EMPTY_KEY=\"\"\n")
        ->and($secondWrite)->toBe($updated)
        ->and($updated)->not->toContain("EMPTY_KEY=\n");
});

it('writes env files idempotently and creates missing files', function (): void {
    $harness = new InstallScaffoldHarness;
    $path = install_scaffold_temp_dir().'/.env';

    expect($harness->writeEnvFile($path, [
        'FIRST_KEY' => 'first',
        'SECOND_KEY' => 'second value',
    ]))->toBeTrue();

    $contents = (string) file_get_contents($path);

    expect($contents)->toContain("FIRST_KEY=first\n")
        ->and($contents)->toContain("SECOND_KEY=\"second value\"\n");

    expect($harness->writeEnvFile($path, [
        'FIRST_KEY' => 'first',
        'SECOND_KEY' => 'second value',
    ]))->toBeFalse()
        ->and(substr_count((string) file_get_contents($path), 'FIRST_KEY='))->toBe(1)
        ->and(substr_count((string) file_get_contents($path), 'SECOND_KEY='))->toBe(1);
});

it('throws when env files cannot be written', function (): void {
    $harness = new InstallScaffoldHarness;
    $path = install_scaffold_temp_dir().'/missing-parent/.env';

    expect(fn () => $harness->writeEnvFile($path, ['KEY' => 'value']))
        ->toThrow(RuntimeException::class, "Unable to write env file at {$path}.");
});

it('pins composer constraints while preserving other require entries', function (): void {
    $harness = new InstallScaffoldHarness;
    $path = install_scaffold_temp_dir().'/composer.json';

    file_put_contents($path, json_encode([
        'name' => 'test/app',
        'require' => [
            'php' => '^8.3',
        ],
        'autoload' => [
            'psr-4' => ['App\\' => 'app/'],
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES).PHP_EOL);

    $harness->pinComposerConstraint($path, 'vendor/pkg', 3);
    $firstWrite = (string) file_get_contents($path);
    $decoded = json_decode($firstWrite, true, flags: JSON_THROW_ON_ERROR);

    expect($decoded['require']['vendor/pkg'])->toBe('^3')
        ->and($decoded['require']['php'])->toBe('^8.3')
        ->and($decoded['autoload']['psr-4']['App\\'])->toBe('app/');

    $harness->pinComposerConstraint($path, 'vendor/pkg', 3);

    expect((string) file_get_contents($path))->toBe($firstWrite);
});

it('throws when composer constraints cannot be written', function (): void {
    $harness = new InstallScaffoldHarness;
    $path = install_scaffold_temp_dir().'/missing-parent/composer.json';

    expect(fn () => $harness->pinComposerConstraint($path, 'vendor/pkg', 3))
        ->toThrow(RuntimeException::class, "Unable to write composer.json at {$path}.");
});

it('runs end to end from a consuming artisan command, minting the operator credential through the scaffold', function (): void {
    app(Kernel::class)->registerCommand(new InstallFixtureCommand);

    $dir = install_scaffold_temp_dir();
    $envPath = $dir.'/.env';
    $composerPath = $dir.'/composer.json';

    file_put_contents($composerPath, json_encode(['name' => 'test/app'], JSON_PRETTY_PRINT).PHP_EOL);

    $exitCode = Artisan::call('fixture:install', [
        '--env-path' => $envPath,
        '--composer-path' => $composerPath,
        '--some-flag' => 'from flag',
        '--package' => 'vendor/pkg',
        '--major' => '4',
    ]);

    $output = Artisan::output();
    $composer = json_decode((string) file_get_contents($composerPath), true, flags: JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(InstallFixtureCommand::SUCCESS)
        ->and((string) file_get_contents($envPath))->toContain("SOME_FLAG=\"from flag\"\n")
        ->and((string) file_get_contents($envPath))->toContain("INSTALL_PACKAGE=vendor/pkg\n")
        ->and($composer['require']['vendor/pkg'])->toBe('^4')
        ->and($output)->toContain('Install summary:');

    // PRD 1.20 through the SCAFFOLD entry point, not the command alone:
    // the install run minted the operator credential and revealed its
    // secret exactly once, through the installer command's own output —
    // without persisting its plaintext.
    $credential = Credential::query()->sole();

    preg_match('/shown once: (\S+)/', $output, $matches);

    expect($credential->subject_type)->toBe(SubjectType::Operator)
        ->and($credential->secret_hash)->toBe(hash('sha256', $matches[1]))
        ->and(substr_count($output, $matches[1]))->toBe(1);
});

it('re-runs the install scaffold without silently minting a second operator credential', function (): void {
    app(Kernel::class)->registerCommand(new InstallFixtureCommand);

    $dir = install_scaffold_temp_dir();
    $arguments = [
        '--env-path' => $dir.'/.env',
        '--composer-path' => $dir.'/composer.json',
    ];

    file_put_contents($dir.'/composer.json', json_encode(['name' => 'test/app'], JSON_PRETTY_PRINT).PHP_EOL);

    expect(Artisan::call('fixture:install', $arguments))->toBe(InstallFixtureCommand::SUCCESS)
        ->and(Credential::query()->count())->toBe(1);

    // The re-run: skip WITH a notice — never a silent second credential.
    expect(Artisan::call('fixture:install', $arguments))->toBe(InstallFixtureCommand::SUCCESS);

    $rerunOutput = Artisan::output();

    expect($rerunOutput)->toContain('already exists; skipping the install mint')
        ->and($rerunOutput)->not->toContain('shown once')
        ->and(Credential::query()->count())->toBe(1);
});

it('validates the complete server request before writing either target without leaking values', function (array $environment, array $requirements): void {
    Process::fake();
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    $secret = 'test-created-sensitive-value';
    file_put_contents($env, "KEEP=unchanged\n");
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");
    $before = install_scaffold_snapshot($dir);

    try {
        (new ServerScaffold)->install($env, $composer, $environment, $requirements);
    } catch (InvalidArgumentException $exception) {
        expect($exception->getMessage())->not->toContain($secret)
            ->and(install_scaffold_snapshot($dir))->toBe($before);
        Process::assertNothingRan();

        return;
    }

    $this->fail('The invalid complete install request was accepted.');
})->with([
    'env key' => [['BAD-KEY' => 'test-created-sensitive-value'], ['vendor/package' => '^1.0']],
    'env value type' => [['GOOD_KEY' => ['test-created-sensitive-value']], ['vendor/package' => '^1.0']],
    'package' => [['GOOD_KEY' => 'test-created-sensitive-value'], ['Vendor/Package;rm' => '^1.0']],
    'uppercase package' => [['GOOD_KEY' => 'test-created-sensitive-value'], ['Vendor/package' => '^1.0']],
    'constraint' => [['GOOD_KEY' => 'test-created-sensitive-value'], ['vendor/package' => '|| test-created-sensitive-value']],
]);

it('removes a rejected Composer value from the complete throwable chain', function (): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    $sensitive = 'test-created-sensitive-constraint-'.bin2hex(random_bytes(8));
    file_put_contents($env, "KEEP=unchanged\n");
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");
    $before = install_scaffold_snapshot($dir);

    try {
        (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], [
            'vendor/package' => '|| '.$sensitive,
        ]);
    } catch (Throwable $exception) {
        expect((string) $exception)->not->toContain($sensitive)
            ->and($exception->getPrevious())->toBeNull()
            ->and(install_scaffold_snapshot($dir))->toBe($before);

        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            expect($current->getMessage())->not->toContain($sensitive)
                ->and((string) $current)->not->toContain($sensitive);
        }

        return;
    }

    $this->fail('The sensitive invalid Composer constraint was accepted.');
});

it('preserves unrelated Composer object and list representations', function (): void {
    $dir = install_scaffold_temp_dir();
    $composer = $dir.'/composer.json';
    file_put_contents($composer, <<<'JSON'
{
    "name": "fixture/app",
    "description": "Fixture",
    "license": "MIT",
    "require": {
        "keep/package": "^9"
    },
    "require-dev": {},
    "extra": {
        "empty_object": {},
        "empty_list": [],
        "objects_in_list": [{}, {"nested": {}}]
    }
}
JSON.PHP_EOL);

    $service = new ServerScaffold;
    $first = $service->writeComposer($composer, ['vendor/package' => '^2']);
    $firstBytes = (string) file_get_contents($composer);
    $firstInode = fileinode($composer);
    touch($composer, 946684800);
    $second = $service->writeComposer($composer, ['vendor/package' => '^2']);
    $document = json_decode((string) file_get_contents($composer), flags: JSON_THROW_ON_ERROR);

    expect($first)->toBe(InstallTargetState::Replaced)
        ->and($second)->toBe(InstallTargetState::Unchanged)
        ->and((string) file_get_contents($composer))->toBe($firstBytes)
        ->and(fileinode($composer))->toBe($firstInode)
        ->and(filemtime($composer))->toBe(946684800)
        ->and($document->{'require-dev'})->toBeInstanceOf(stdClass::class)
        ->and($document->extra->empty_object)->toBeInstanceOf(stdClass::class)
        ->and($document->extra->empty_list)->toBe([])
        ->and($document->extra->objects_in_list[0])->toBeInstanceOf(stdClass::class)
        ->and($document->extra->objects_in_list[1]->nested)->toBeInstanceOf(stdClass::class)
        ->and($document->require->{'keep/package'})->toBe('^9')
        ->and($document->require->{'vendor/package'})->toBe('^2');

    (new Symfony\Component\Process\Process([
        'composer', 'validate', '--no-check-publish', '--no-check-lock', $composer,
    ]))->mustRun();
});

it('rejects list-shaped Composer roots and require members before writing either target', function (string $contents): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($env, "KEEP=unchanged\n");
    file_put_contents($composer, $contents);
    $before = install_scaffold_snapshot($dir);

    expect(fn () => (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], ['vendor/package' => '^1']))
        ->toThrow(RuntimeException::class)
        ->and(install_scaffold_snapshot($dir))->toBe($before);
})->with([
    'list root' => "[]\n",
    'list require' => "{\"name\":\"fixture/app\",\"require\":[]}\n",
]);

it('uses the installed Composer validators for accepted package names and constraints', function (): void {
    $dir = install_scaffold_temp_dir();
    $composer = $dir.'/composer.json';
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");

    expect(class_exists(VersionParser::class))->toBeTrue();
    $state = (new ServerScaffold)->writeComposer($composer, ['vendor-name/package.name' => '^1.2 || ^2.0']);
    $document = json_decode((string) file_get_contents($composer), true, flags: JSON_THROW_ON_ERROR);

    expect($state)->toBe(InstallTargetState::Replaced)
        ->and($document['require'])->toBe(['vendor-name/package.name' => '^1.2 || ^2.0']);
});

it('rejects relative traversal symlink and missing composer target paths before writes', function (string $case): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");

    if ($case === 'relative') {
        $env = '.env';
    } elseif ($case === 'traversal') {
        $env = $dir.'/nested/../.env';
    } elseif ($case === 'symlink') {
        file_put_contents($dir.'/actual-env', 'KEEP=yes');
        symlink($dir.'/actual-env', $env);
    } else {
        $composer = $dir.'/missing.json';
    }

    $before = install_scaffold_snapshot($dir);
    expect(fn () => (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], ['vendor/package' => '^1']))
        ->toThrow(InvalidArgumentException::class)
        ->and(install_scaffold_snapshot($dir))->toBe($before);
})->with(['relative', 'traversal', 'symlink', 'missing composer']);

it('uses persistent sidecar locks and atomic mode-preserving replacement with byte-idempotent reruns', function (): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($env, "KEEP=yes\nCHANGE=old\n");
    chmod($env, 0640);
    file_put_contents($composer, "{\n    \"name\": \"fixture/app\",\n    \"extra\": {\"keep\": true}\n}\n");
    chmod($composer, 0644);
    $oldEnvInode = fileinode($env);
    $oldComposerInode = fileinode($composer);

    $service = new ServerScaffold;
    $first = $service->install($env, $composer, ['CHANGE' => 'new'], ['vendor/package' => '^2.3']);
    $envLock = $env.'.bfc.lock';
    $composerLock = $composer.'.bfc.lock';
    $envLockInode = fileinode($envLock);
    $composerLockInode = fileinode($composerLock);
    $envInode = fileinode($env);
    $composerInode = fileinode($composer);
    touch($env, 946684800);
    touch($composer, 946684800);

    $second = $service->install($env, $composer, ['CHANGE' => 'new'], ['vendor/package' => '^2.3']);

    expect($first->stages())->toBe(['environment' => 'replaced', 'composer' => 'replaced'])
        ->and($second->stages())->toBe(['environment' => 'unchanged', 'composer' => 'unchanged'])
        ->and($envInode)->not->toBe($oldEnvInode)
        ->and($composerInode)->not->toBe($oldComposerInode)
        ->and(fileinode($env))->toBe($envInode)
        ->and(fileinode($composer))->toBe($composerInode)
        ->and(filemtime($env))->toBe(946684800)
        ->and(filemtime($composer))->toBe(946684800)
        ->and(fileinode($envLock))->toBe($envLockInode)
        ->and(fileinode($composerLock))->toBe($composerLockInode)
        ->and(fileperms($env) & 0777)->toBe(0640)
        ->and(fileperms($composer) & 0777)->toBe(0644)
        ->and((string) file_get_contents($env))->toContain("KEEP=yes\n", "CHANGE=new\n")
        ->and(json_decode((string) file_get_contents($composer), true)['extra'])->toBe(['keep' => true]);
});

it('creates new environment files as owner-only', function (): void {
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");

    $result = (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], []);

    expect($result->environment)->toBe(InstallTargetState::Replaced)
        ->and(fileperms($env) & 0777)->toBe(0600);
});

it('reports env success and composer failure then retries without rewriting env', function (): void {
    $root = install_scaffold_temp_dir();
    $envDir = $root.'/env';
    $composerDir = $root.'/composer';
    mkdir($envDir);
    mkdir($composerDir);
    $env = $envDir.'/.env';
    $composer = $composerDir.'/composer.json';
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");
    chmod($composerDir, 0555);

    try {
        $first = (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], ['vendor/package' => '^1']);
    } finally {
        chmod($composerDir, 0755);
    }

    $envInode = fileinode($env);
    touch($env, 946684800);
    $second = (new ServerScaffold)->install($env, $composer, ['SAFE_KEY' => 'safe'], ['vendor/package' => '^1']);

    expect($first->stages())->toBe(['environment' => 'replaced', 'composer' => 'failed'])
        ->and($second->stages())->toBe(['environment' => 'unchanged', 'composer' => 'replaced'])
        ->and(fileinode($env))->toBe($envInode)
        ->and(filemtime($env))->toBe(946684800);
});

it('passes force explicitly through the installer adapter', function (): void {
    app(Kernel::class)->registerCommand(new InstallFixtureCommand);
    $dir = install_scaffold_temp_dir();
    file_put_contents($dir.'/composer.json', "{\"name\":\"fixture/app\"}\n");
    $arguments = ['--env-path' => $dir.'/.env', '--composer-path' => $dir.'/composer.json'];

    expect(Artisan::call('fixture:install', $arguments))->toBe(0)
        ->and(Artisan::call('fixture:install', $arguments + ['--force' => true]))->toBe(0)
        ->and(Credential::query()->count())->toBe(2);
});

it('reports file success when mint fails and retries mint without rewriting files', function (): void {
    $kernel = app(Kernel::class);
    $kernel->registerCommand(new InstallFixtureCommand);
    $kernel->registerCommand(new FailingInstallMintCommand);
    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($composer, "{\"name\":\"fixture/app\"}\n");
    $arguments = ['--env-path' => $env, '--composer-path' => $composer];

    expect(Artisan::call('fixture:install', $arguments))->toBe(Command::FAILURE)
        ->and(Artisan::output())->toContain('environment: replaced', 'composer: replaced')
        ->and(Credential::query()->count())->toBe(0);

    $envInode = fileinode($env);
    $composerInode = fileinode($composer);
    touch($env, 946684800);
    touch($composer, 946684800);
    $kernel->registerCommand(new InstallOperatorCredentialCommand);

    expect(Artisan::call('fixture:install', $arguments))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('environment: unchanged', 'composer: unchanged', 'shown once')
        ->and(fileinode($env))->toBe($envInode)
        ->and(fileinode($composer))->toBe($composerInode)
        ->and(filemtime($env))->toBe(946684800)
        ->and(filemtime($composer))->toBe(946684800)
        ->and(Credential::query()->count())->toBe(1);
});

it('coordinates concurrent default installers and observes the documented extra revocable credentials', function (): void {
    if (! function_exists('posix_mkfifo')) {
        $this->fail('The install concurrency barrier requires posix_mkfifo.');
    }

    $dir = install_scaffold_temp_dir();
    $database = $dir.'/install.sqlite';
    touch($database);
    $fixture = __DIR__.'/Fixtures/concurrent-install-mint.php';
    $setup = new Symfony\Component\Process\Process([PHP_BINARY, $fixture, 'setup', $database]);
    $setup->mustRun();
    $barriers = [];
    $workers = [];

    foreach ([1, 2] as $worker) {
        $ready = $dir."/ready-{$worker}.fifo";
        $go = $dir."/go-{$worker}.fifo";
        posix_mkfifo($ready, 0600);
        posix_mkfifo($go, 0600);
        $barriers[] = [$ready, $go];
        $process = new Symfony\Component\Process\Process([PHP_BINARY, $fixture, 'install', $database, $ready, $go]);
        $process->start();
        $workers[] = $process;
    }

    foreach ($barriers as [$ready]) {
        $pipe = fopen($ready, 'rb');
        expect($pipe)->not->toBeFalse();
        expect(fread($pipe, 1))->toBe('1');
        fclose($pipe);
    }

    foreach ($barriers as [, $go]) {
        $pipe = fopen($go, 'wb');
        expect($pipe)->not->toBeFalse();
        fwrite($pipe, '1');
        fclose($pipe);
    }

    foreach ($workers as $worker) {
        $worker->wait();
        expect($worker->getExitCode())->toBe(0, $worker->getErrorOutput());
    }

    $inspect = new Symfony\Component\Process\Process([PHP_BINARY, $fixture, 'inspect', $database]);
    $inspect->mustRun();
    expect((int) trim($inspect->getOutput()))->toBe(2);
});

it('serializes concurrent scaffold writers through the stable target sidecars', function (): void {
    if (! function_exists('posix_mkfifo')) {
        $this->fail('The scaffold concurrency barrier requires posix_mkfifo.');
    }

    $dir = install_scaffold_temp_dir();
    $env = $dir.'/.env';
    $composer = $dir.'/composer.json';
    file_put_contents($env, "KEEP=unchanged\n");
    chmod($env, 0640);
    file_put_contents($composer, "{\"name\":\"fixture/app\",\"require\":{\"keep/package\":\"^9\"}}\n");
    chmod($composer, 0644);

    $envLock = fopen($env.'.bfc.lock', 'c+b');
    $composerLock = fopen($composer.'.bfc.lock', 'c+b');
    expect($envLock)->not->toBeFalse()
        ->and($composerLock)->not->toBeFalse()
        ->and(flock($envLock, LOCK_EX))->toBeTrue()
        ->and(flock($composerLock, LOCK_EX))->toBeTrue();

    $fixture = __DIR__.'/Fixtures/concurrent-server-scaffold.php';
    $barriers = [];
    $workers = [];
    $locksHeld = true;

    try {
        foreach (['one', 'two'] as $worker) {
            $ready = $dir."/ready-{$worker}.fifo";
            $go = $dir."/go-{$worker}.fifo";
            $attempting = $dir."/attempting-{$worker}.fifo";
            posix_mkfifo($ready, 0600);
            posix_mkfifo($go, 0600);
            posix_mkfifo($attempting, 0600);
            $barriers[] = [$ready, $go, $attempting];
            $process = new Symfony\Component\Process\Process([
                PHP_BINARY, $fixture, $env, $composer, $ready, $go, $attempting, $worker,
            ]);
            $process->start();
            $workers[] = $process;
        }

        foreach ($barriers as [$ready]) {
            $pipe = fopen($ready, 'rb');
            expect($pipe)->not->toBeFalse()
                ->and(fread($pipe, 1))->toBe('1');
            fclose($pipe);
        }

        foreach ($barriers as [, $go]) {
            $pipe = fopen($go, 'wb');
            expect($pipe)->not->toBeFalse()
                ->and(fwrite($pipe, '1'))->toBe(1);
            fclose($pipe);
        }

        foreach ($barriers as [, , $attempting]) {
            $pipe = fopen($attempting, 'rb');
            expect($pipe)->not->toBeFalse()
                ->and(fread($pipe, 1))->toBe('1');
            fclose($pipe);
        }

        foreach ($workers as $worker) {
            expect($worker->isRunning())->toBeTrue()
                ->and($worker->getOutput())->toBe('');
        }
        expect((string) file_get_contents($env))->toBe("KEEP=unchanged\n")
            ->and((string) file_get_contents($composer))->toBe("{\"name\":\"fixture/app\",\"require\":{\"keep/package\":\"^9\"}}\n");

        flock($envLock, LOCK_UN);
        flock($composerLock, LOCK_UN);
        $locksHeld = false;

        foreach ($workers as $worker) {
            $worker->wait();
            expect($worker->isRunning())->toBeFalse()
                ->and($worker->getExitCode())->toBe(0, $worker->getErrorOutput())
                ->and(json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR))->toBe([
                    'environment' => 'replaced',
                    'composer' => 'replaced',
                ]);
        }
    } finally {
        if ($locksHeld) {
            flock($envLock, LOCK_UN);
            flock($composerLock, LOCK_UN);
        }
        fclose($envLock);
        fclose($composerLock);

        foreach ($workers as $worker) {
            if ($worker->isRunning()) {
                $worker->stop(1);
            }
        }
    }

    $loaded = Dotenv::createArrayBacked($dir)->load();
    $document = json_decode((string) file_get_contents($composer), flags: JSON_THROW_ON_ERROR);

    expect($loaded['KEEP'])->toBe('unchanged')
        ->and($loaded['WORKER_ONE'])->toBe('first')
        ->and($loaded['WORKER_TWO'])->toBe('second')
        ->and($document->require->{'keep/package'})->toBe('^9')
        ->and($document->require->{'worker/one'})->toBe('^1')
        ->and($document->require->{'worker/two'})->toBe('^2')
        ->and(fileperms($env) & 0777)->toBe(0640)
        ->and(fileperms($composer) & 0777)->toBe(0644)
        ->and(glob($dir.'/.bfc-install-*') ?: [])->toBe([]);

    (new Symfony\Component\Process\Process([
        'composer', 'validate', '--no-check-publish', '--no-check-lock', $composer,
    ]))->mustRun();
});
