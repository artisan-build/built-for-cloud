<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands\Concerns;

use ArtisanBuild\BuiltForCloud\Install\InstallResult;
use ArtisanBuild\BuiltForCloud\Install\InstallTargetState;
use ArtisanBuild\BuiltForCloud\Install\ServerScaffold;
use Illuminate\Console\Command;
use RuntimeException;

trait WritesInstallEnv
{
    /**
     * The install scaffold's mint step (PRD 1.20): an app's install
     * command calls this to mint the operator credential a fresh install
     * needs instead of an environment pseudo-credential. It runs
     * `bfc:install:operator-credential` in-process (the --local mint
     * action; zero Cloud dependency), with the one-time TTY reveal
     * flowing through the calling command's own output.
     *
     * IDEMPOTENT: the underlying command skips with a notice when a live
     * operator credential already exists, so re-running an installer
     * never silently mints a second credential.
     */
    final public function mintInstallOperatorCredential(?string $ref = null, ?string $name = null, bool $force = false): int
    {
        if (! $this instanceof Command) {
            throw new RuntimeException('WritesInstallEnv::mintInstallOperatorCredential must be used from an Illuminate console command.');
        }

        $options = [];

        if ($ref !== null) {
            $options['--ref'] = $ref;
        }

        if ($name !== null) {
            $options['--name'] = $name;
        }

        if ($force) {
            $options['--force'] = true;
        }

        return $this->call('bfc:install:operator-credential', $options);
    }

    final public function setEnvironmentValue(string $contents, string $key, string $value): string
    {
        return (new ServerScaffold)->setEnvironmentValue($contents, $key, $value);
    }

    /**
     * @param  array<string, string>  $environment
     * @param  array<string, string>  $requirements
     */
    final public function installServerScaffold(
        string $environmentPath,
        string $composerPath,
        array $environment,
        array $requirements,
    ): InstallResult {
        return (new ServerScaffold)->install($environmentPath, $composerPath, $environment, $requirements);
    }

    /**
     * @param  array<string, string>  $values
     */
    final public function writeEnvFile(string $path, array $values): bool
    {
        try {
            return (new ServerScaffold)->writeEnvironment($path, $values) === InstallTargetState::Replaced;
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new RuntimeException("Unable to write env file at {$path}.", previous: $exception);
        }
    }

    final public function pinComposerConstraint(string $composerJsonPath, string $package, int $major): void
    {
        try {
            (new ServerScaffold)->writeComposer($composerJsonPath, [$package => '^'.$major]);
        } catch (RuntimeException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new RuntimeException("Unable to write composer.json at {$composerJsonPath}.", previous: $exception);
        }
    }

    /**
     * @param  array<string, string|bool|int|null>  $changes
     */
    final public function summarize(array $changes): void
    {
        if (! $this instanceof Command) {
            throw new RuntimeException('WritesInstallEnv::summarize must be used from an Illuminate console command.');
        }

        $this->line('Install summary:');

        foreach ($changes as $label => $value) {
            $this->line(' - '.$label.': '.$this->summaryValue($value));
        }
    }

    private function summaryValue(string|bool|int|null $value): string
    {
        return match (true) {
            is_bool($value) => $value ? 'yes' : 'no',
            $value === null => 'none',
            default => (string) $value,
        };
    }
}
