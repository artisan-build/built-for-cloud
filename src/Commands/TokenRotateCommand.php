<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;

final class TokenRotateCommand extends Command
{
    protected $signature = 'token:rotate {name} {--emergency} {--execute} {--hash=} {--environment=}';

    protected $description = 'Rotate a Built for Cloud API token';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');
        $emergency = (bool) $this->option('emergency');

        if ((bool) $this->option('execute')) {
            $registry->rotate($name, (string) $this->option('hash'), $emergency);
            $this->line($emergency ? "Token {$name} rotated with emergency expiry." : "Token {$name} rotated with one hour grace.");

            return self::SUCCESS;
        }

        $generated = $generator->generate();
        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $command = 'token:rotate '.$this->quote($name).' --execute --hash='.$generated->hash;

        if ($emergency) {
            $command .= ' --emergency';
        }

        $result = $runner->run($environment, $command);

        $this->line($result['output']);

        if ($result['exitCode'] !== self::SUCCESS) {
            return $result['exitCode'];
        }

        $this->line('Save this token - shown once: '.$generated->plaintext);

        return self::SUCCESS;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function quote(string $value): string
    {
        return escapeshellarg($value);
    }
}
