<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\InstallFixtureCommand;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Artisan;

final class InstallScaffoldHarness
{
    use WritesInstallEnv;
}

function install_scaffold_temp_dir(): string
{
    $path = sys_get_temp_dir().'/bfc-install-'.bin2hex(random_bytes(6));

    mkdir($path);

    return $path;
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

it('runs end to end from a consuming artisan command', function (): void {
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

    $composer = json_decode((string) file_get_contents($composerPath), true, flags: JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(InstallFixtureCommand::SUCCESS)
        ->and((string) file_get_contents($envPath))->toContain("SOME_FLAG=\"from flag\"\n")
        ->and((string) file_get_contents($envPath))->toContain("INSTALL_PACKAGE=vendor/pkg\n")
        ->and($composer['require']['vendor/pkg'])->toBe('^4')
        ->and(Artisan::output())->toContain('Install summary:');
});
