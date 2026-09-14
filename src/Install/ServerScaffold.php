<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Install;

use Composer\Semver\VersionParser;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * Applies local install inputs without discovering or contacting Cloud.
 * Each target is independently atomic; cross-file atomicity is not claimed.
 */
final class ServerScaffold
{
    /**
     * @param  array<string, string>  $environment
     * @param  array<string, string>  $requirements
     */
    public function install(
        string $environmentPath,
        string $composerPath,
        array $environment,
        array $requirements,
    ): InstallResult {
        $this->validatePath($environmentPath, false);
        $this->validatePath($composerPath, true);
        $this->validateEnvironment($environment);
        $this->validateRequirements($requirements);

        // Decode and transform both inputs before the first write. A rejected
        // request or malformed existing target therefore changes neither file.
        $this->environmentContents($this->readExisting($environmentPath, false), $environment);
        $this->composerContents($this->readExisting($composerPath, true), $requirements);

        try {
            $environmentState = $this->replaceLocked(
                $environmentPath,
                fn (string $contents): string => $this->environmentContents($contents, $environment),
                0600,
                false,
            );
        } catch (Throwable) {
            return new InstallResult(InstallTargetState::Failed, InstallTargetState::Failed);
        }

        try {
            $composerState = $this->replaceLocked(
                $composerPath,
                fn (string $contents): string => $this->composerContents($contents, $requirements),
                0644,
                true,
            );
        } catch (Throwable) {
            return new InstallResult($environmentState, InstallTargetState::Failed);
        }

        return new InstallResult($environmentState, $composerState);
    }

    /** @param array<string, string> $values */
    public function writeEnvironment(string $path, array $values): InstallTargetState
    {
        $this->validatePath($path, false);
        $this->validateEnvironment($values);
        $this->environmentContents($this->readExisting($path, false), $values);

        return $this->replaceLocked(
            $path,
            fn (string $contents): string => $this->environmentContents($contents, $values),
            0600,
            false,
        );
    }

    /** @param array<string, string> $requirements */
    public function writeComposer(string $path, array $requirements): InstallTargetState
    {
        $this->validatePath($path, true);
        $this->validateRequirements($requirements);
        $this->composerContents($this->readExisting($path, true), $requirements);

        return $this->replaceLocked(
            $path,
            fn (string $contents): string => $this->composerContents($contents, $requirements),
            0644,
            true,
        );
    }

    public function setEnvironmentValue(string $contents, string $key, string $value): string
    {
        $this->validateEnvironment([$key => $value]);
        $line = $key.'='.$this->formatEnvironmentValue($value);
        $pattern = '/^'.preg_quote($key, '/').'=.*$/m';

        if (preg_match($pattern, $contents) === 1) {
            return (string) preg_replace($pattern, $line, $contents);
        }

        $contents = rtrim($contents, "\r\n");

        return ($contents === '' ? '' : $contents.PHP_EOL).$line.PHP_EOL;
    }

    private function validatePath(string $path, bool $mustExist): void
    {
        if ($path === '' || str_contains($path, "\0") || ! str_starts_with($path, DIRECTORY_SEPARATOR)) {
            throw new InvalidArgumentException('Install target paths must be absolute.');
        }

        $segments = explode(DIRECTORY_SEPARATOR, $path);
        $parent = realpath(dirname($path));

        if (! is_string($parent)
            || in_array('.', $segments, true)
            || in_array('..', $segments, true)
            || is_link($path)
            || is_link($path.'.bfc.lock')
            || ($mustExist && ! is_file($path))) {
            throw new InvalidArgumentException('An install target path is invalid.');
        }
    }

    /** @param array<mixed, mixed> $values */
    private function validateEnvironment(array $values): void
    {
        foreach ($values as $key => $value) {
            if (! is_string($key)
                || preg_match('/^[A-Z][A-Z0-9_]*$/D', $key) !== 1
                || ! is_string($value)) {
                throw new InvalidArgumentException('The environment map is invalid.');
            }
        }
    }

    /** @param array<mixed, mixed> $requirements */
    private function validateRequirements(array $requirements): void
    {
        $parser = new VersionParser;

        foreach ($requirements as $package => $constraint) {
            if (! is_string($package)
                || ! is_string($constraint)
                || preg_match('{^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]?|-{0,2})[a-z0-9]+)*$}D', $package) !== 1) {
                throw new InvalidArgumentException('The Composer requirements are invalid.');
            }

            try {
                $parser->parseConstraints($constraint);
            } catch (Throwable $exception) {
                throw new InvalidArgumentException('The Composer requirements are invalid.', previous: $exception);
            }
        }
    }

    /** @param array<string, string> $values */
    private function environmentContents(string $contents, array $values): string
    {
        foreach ($values as $key => $value) {
            $contents = $this->setEnvironmentValue($contents, $key, $value);
        }

        return $contents;
    }

    /** @param array<string, string> $requirements */
    private function composerContents(string $contents, array $requirements): string
    {
        try {
            $composer = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('The Composer target is not valid JSON.', previous: $exception);
        }

        if (! is_array($composer) || ($composer !== [] && array_is_list($composer))) {
            throw new RuntimeException('The Composer target must contain an object.');
        }

        $require = $composer['require'] ?? [];

        if (! is_array($require) || ($require !== [] && array_is_list($require))) {
            throw new RuntimeException('The Composer require member must contain an object.');
        }

        foreach ($requirements as $package => $constraint) {
            $require[$package] = $constraint;
        }

        if (($composer['require'] ?? []) === $require) {
            return $contents;
        }

        $composer['require'] = $require;

        return json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR).PHP_EOL;
    }

    /** @param callable(string): string $transform */
    private function replaceLocked(
        string $path,
        callable $transform,
        int $createMode,
        bool $mustExist,
    ): InstallTargetState {
        $lock = fopen($path.'.bfc.lock', 'c+b');

        if ($lock === false || ! flock($lock, LOCK_EX)) {
            throw new RuntimeException('The install target lock could not be acquired.');
        }

        try {
            $original = $this->readExisting($path, $mustExist);
            $contents = $transform($original);

            if ($contents === $original) {
                return InstallTargetState::Unchanged;
            }

            $mode = is_file($path) ? (fileperms($path) & 0777) : $createMode;
            $temporary = tempnam(dirname($path), '.bfc-install-');

            if (! is_string($temporary)) {
                throw new RuntimeException('A same-directory temporary file could not be created.');
            }

            try {
                if (! chmod($temporary, $mode) || file_put_contents($temporary, $contents) === false) {
                    throw new RuntimeException('The install target temporary file could not be written.');
                }

                if (! rename($temporary, $path)) {
                    throw new RuntimeException('The install target could not be atomically replaced.');
                }
            } finally {
                if (is_file($temporary)) {
                    @unlink($temporary);
                }
            }

            return InstallTargetState::Replaced;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function readExisting(string $path, bool $mustExist): string
    {
        if (! is_file($path)) {
            if ($mustExist) {
                throw new RuntimeException('A required install target is missing.');
            }

            return '';
        }

        $contents = file_get_contents($path);

        return is_string($contents)
            ? $contents
            : throw new RuntimeException('An install target could not be read.');
    }

    private function formatEnvironmentValue(string $value): string
    {
        if ($value !== '' && preg_match('/^[A-Za-z0-9_:\/.@-]+$/', $value) === 1) {
            return $value;
        }

        return '"'.str_replace(['\\', '"', "\n", "\r", '='], ['\\\\', '\\"', '\\n', '', '\\='], $value).'"';
    }
}
