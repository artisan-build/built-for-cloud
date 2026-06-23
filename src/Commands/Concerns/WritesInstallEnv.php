<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands\Concerns;

use Illuminate\Console\Command;
use JsonException;
use RuntimeException;

trait WritesInstallEnv
{
    final public function setEnvironmentValue(string $contents, string $key, string $value): string
    {
        $line = $key.'='.$this->formatEnvironmentValue($value);
        $pattern = '/^'.preg_quote($key, '/').'=.*$/m';

        if (preg_match($pattern, $contents) === 1) {
            return (string) preg_replace($pattern, $line, $contents);
        }

        $contents = rtrim($contents, "\r\n");

        return ($contents === '' ? '' : $contents.PHP_EOL).$line.PHP_EOL;
    }

    /**
     * @param  array<string, string>  $values
     */
    final public function writeEnvFile(string $path, array $values): bool
    {
        $original = is_file($path) ? (string) file_get_contents($path) : '';
        $contents = $original;

        foreach ($values as $key => $value) {
            $contents = $this->setEnvironmentValue($contents, $key, $value);
        }

        if ($contents === $original) {
            return false;
        }

        if (@file_put_contents($path, $contents) === false) {
            throw new RuntimeException("Unable to write env file at {$path}.");
        }

        return true;
    }

    final public function pinComposerConstraint(string $composerJsonPath, string $package, int $major): void
    {
        $original = is_file($composerJsonPath) ? (string) file_get_contents($composerJsonPath) : '{}';
        $composer = $this->decodeComposerJson($original, $composerJsonPath);
        $constraint = '^'.$major;

        $require = [];

        if (isset($composer['require']) && is_array($composer['require'])) {
            foreach ($composer['require'] as $requiredPackage => $requiredConstraint) {
                if (is_string($requiredPackage)) {
                    $require[$requiredPackage] = $requiredConstraint;
                }
            }
        }

        if (($require[$package] ?? null) === $constraint) {
            return;
        }

        $require[$package] = $constraint;
        $composer['require'] = $require;

        $written = @file_put_contents(
            $composerJsonPath,
            json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR).PHP_EOL,
        );

        if ($written === false) {
            throw new RuntimeException("Unable to write composer.json at {$composerJsonPath}.");
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

    private function formatEnvironmentValue(string $value): string
    {
        if ($value !== '' && preg_match('/^[A-Za-z0-9_:\/.@-]+$/', $value) === 1) {
            return $value;
        }

        // A lone carriage return is dropped so generated .env files cannot break CRLF boundaries.
        return '"'.str_replace(['\\', '"', "\n", "\r", '='], ['\\\\', '\\"', '\\n', '', '\\='], $value).'"';
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeComposerJson(string $contents, string $path): array
    {
        try {
            $decoded = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException("Unable to decode composer.json at {$path}.", previous: $exception);
        }

        if (! is_array($decoded)) {
            throw new RuntimeException("Composer file at {$path} must contain a JSON object.");
        }

        $result = [];

        foreach ($decoded as $key => $value) {
            if (! is_string($key)) {
                throw new RuntimeException("Composer file at {$path} must contain a JSON object.");
            }

            $result[$key] = $value;
        }

        return $result;
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
