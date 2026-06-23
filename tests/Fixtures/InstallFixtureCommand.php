<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use Illuminate\Console\Command;

final class InstallFixtureCommand extends Command
{
    use WritesInstallEnv;

    protected $signature = 'fixture:install {--env-path=} {--composer-path=} {--some-flag=} {--package=vendor/pkg} {--major=2}';

    protected $description = 'Exercise the reusable install scaffold in tests';

    public function handle(): int
    {
        $envPath = $this->stringOption('env-path');
        $composerPath = $this->stringOption('composer-path');
        $someFlag = $this->stringOption('some-flag') ?? 'default value';
        $package = $this->stringOption('package') ?? 'vendor/pkg';
        $major = (int) ($this->stringOption('major') ?? '2');

        if ($envPath === null || $composerPath === null) {
            $this->error('Both --env-path and --composer-path are required.');

            return self::FAILURE;
        }

        $changed = $this->writeEnvFile($envPath, [
            'SOME_FLAG' => $someFlag,
            'INSTALL_PACKAGE' => $package,
        ]);

        $this->pinComposerConstraint($composerPath, $package, $major);

        $this->summarize([
            'env changed' => $changed,
            'package' => $package,
            'constraint' => '^'.$major,
        ]);

        return self::SUCCESS;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
