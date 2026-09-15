<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\Process\Process;

final class P6LiveCommandRunner
{
    /** @return list<string> */
    public static function freshLaravelHostCommand(string $host): array
    {
        return [
            'composer',
            'create-project',
            'laravel/laravel:^13.0',
            $host,
            '--no-interaction',
            '--no-install',
            '--no-scripts',
        ];
    }

    /** @return list<string> */
    public static function archiveInstallCommand(): array
    {
        return [
            'composer',
            'update',
            '--no-interaction',
            '--prefer-dist',
            '--no-scripts',
        ];
    }

    /**
     * @param  list<string>  $command
     * @param  array<string, string>  $environment
     * @param  list<list<string>>  $arguments
     * @param  list<string>  $outputs
     */
    public static function run(
        array $command,
        string $directory,
        array $environment,
        string $label,
        array &$arguments,
        array &$outputs,
    ): string {
        self::assertLabel($label);

        $arguments[] = $command;
        $process = new Process($command, $directory, $environment, null, 300);
        if ($process->run() !== 0) {
            fwrite(STDERR, "P6c live command failed at stage: {$label}\n");

            throw new RuntimeException("{$label} exited non-zero.");
        }

        $output = $process->getOutput();
        $outputs[] = $output.$process->getErrorOutput();

        return $output;
    }

    /**
     * @param  list<string>  $command
     * @param  array<string, string>  $environment
     * @param  list<list<string>>  $arguments
     * @param  list<string>  $diagnostics
     */
    public static function runSensitive(
        array $command,
        string $directory,
        array $environment,
        string $input,
        string $label,
        array &$arguments,
        array &$diagnostics,
    ): string {
        self::assertLabel($label);
        $arguments[] = $command;
        $process = new Process($command, $directory, $environment, $input, 60);
        if ($process->run() !== 0) {
            throw new RuntimeException("{$label} exited non-zero.");
        }

        $diagnostics[] = $process->getErrorOutput();

        return $process->getOutput();
    }

    /** @param list<string> $forbiddenMaterials */
    public static function assertFilesAbsent(string $root, array $forbiddenMaterials): void
    {
        $materials = array_values(array_filter(
            $forbiddenMaterials,
            static fn (string $material): bool => $material !== '',
        ));
        $overlap = $materials === [] ? 0 : max(array_map('strlen', $materials)) - 1;
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $entry) {
            if (! $entry instanceof \SplFileInfo) {
                throw new RuntimeException('The P6c file scan encountered an unsupported path.');
            }
            if ($entry->isLink()) {
                throw new RuntimeException('The P6c file scan encountered an unsupported path.');
            }
            if ($entry->isDir()) {
                continue;
            }
            if (! $entry->isFile()) {
                throw new RuntimeException('The P6c file scan encountered an unsupported path.');
            }

            $stream = @fopen($entry->getPathname(), 'rb');
            if ($stream === false) {
                throw new RuntimeException('The P6c file scan encountered a file that could not be inspected.');
            }

            try {
                $carry = '';
                while (! feof($stream)) {
                    $chunk = fread($stream, 8192);
                    if ($chunk === false) {
                        throw new RuntimeException('The P6c file scan encountered a file that could not be inspected.');
                    }
                    $contents = $carry.$chunk;
                    foreach ($materials as $material) {
                        if (str_contains($contents, $material)) {
                            throw new RuntimeException('The P6c secret detector found forbidden material in a generated file.');
                        }
                    }
                    $carry = $overlap > 0 ? substr($contents, -$overlap) : '';
                }
            } finally {
                fclose($stream);
            }
        }
    }

    private static function assertLabel(string $label): void
    {
        if (preg_match('/\A[A-Za-z][A-Za-z0-9 ._-]{0,79}\z/D', $label) !== 1) {
            throw new InvalidArgumentException('The P6c live command stage label is invalid.');
        }
    }
}
