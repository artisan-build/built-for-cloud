<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;

final class TokenRevokeCommand extends Command
{
    protected $signature = 'token:revoke {name} {--execute} {--environment=}';

    protected $description = 'Revoke Built for Cloud API tokens by name';

    public function handle(CloudCommandRunner $runner, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');

        if ((bool) $this->option('execute')) {
            $count = $registry->revoke($name);
            $this->line("Revoked {$count} active row(s) for {$name}");

            return self::SUCCESS;
        }

        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'token:revoke '.$this->quote($name).' --execute');

        $this->line($result['output']);

        return $result['exitCode'];
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
