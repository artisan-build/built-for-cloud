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
        if (preg_match('/\A[A-Za-z][A-Za-z0-9 ._-]{0,79}\z/D', $label) !== 1) {
            throw new InvalidArgumentException('The P6c live command stage label is invalid.');
        }

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
}
