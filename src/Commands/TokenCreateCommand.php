<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;

final class TokenCreateCommand extends Command
{
    protected $signature = 'token:create {name} {--execute} {--hash=} {--environment=}';

    protected $description = 'Create a Built for Cloud API token';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');

        if ((bool) $this->option('execute')) {
            $registry->store($name, (string) $this->option('hash'));
            $this->line("Token {$name} stored.");

            return self::SUCCESS;
        }

        $generated = $generator->generate();
        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'token:create '.$this->quote($name).' --execute --hash='.$generated->hash);

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
