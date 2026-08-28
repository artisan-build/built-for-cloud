<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\InstallFixtureCommand;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;

uses(RefreshDatabase::class);

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

    expect($updated)->toBe("SECRET=\"a\\nINJECTED\\=yes \\\"quoted\\\"\"\n")
        ->and(substr_count($updated, 'SECRET='))->toBe(1)
        ->and(substr_count($updated, 'INJECTED='))->toBe(0);
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
    // and never wrote a FALLBACK_TOKEN.
    $credential = Credential::query()->sole();

    preg_match('/shown once: (\S+)/', $output, $matches);

    expect($credential->subject_type)->toBe(SubjectType::Operator)
        ->and($credential->secret_hash)->toBe(hash('sha256', $matches[1]))
        ->and(substr_count($output, $matches[1]))->toBe(1)
        ->and((string) file_get_contents($envPath))->not->toContain('FALLBACK_TOKEN');
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
