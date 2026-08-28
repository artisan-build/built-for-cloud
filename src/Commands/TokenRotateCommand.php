<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;

final class TokenRotateCommand extends Command
{
    protected $signature = 'token:rotate {name} {--emergency} {--execute} {--hash=} {--environment=} {--local}';

    protected $description = 'Rotate a Built for Cloud API token';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');
        $emergency = (bool) $this->option('emergency');

        if ((bool) $this->option('execute')) {
            $registry->rotate($name, (string) $this->option('hash'), $emergency, AuditActor::cliOperator());
            $this->line($emergency ? "Token {$name} rotated with emergency expiry." : "Token {$name} rotated with one hour grace.");

            return self::SUCCESS;
        }

        $generated = $generator->generate();

        // `--local` (PRD 1.11): the EXISTING legacy rotation, run against
        // the local database with zero Cloud dependency — transport
        // plumbing only. The unified rotate verb is a later release.
        if ((bool) $this->option('local')) {
            $registry->rotate($name, $generated->hash, $emergency, AuditActor::cliOperator());
            $this->line($emergency ? "Token {$name} rotated with emergency expiry." : "Token {$name} rotated with one hour grace.");
            $this->line('Save this token - shown once: '.$generated->plaintext);

            return self::SUCCESS;
        }
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
