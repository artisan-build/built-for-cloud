<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use Illuminate\Console\Command;

final class FallbackTokenGenerateCommand extends Command
{
    use WritesInstallEnv;

    protected $signature = 'fallback-token:generate {--show} {--path=}';

    protected $description = 'Generate and store a local fallback token';

    public function handle(TokenGenerator $generator): int
    {
        $generated = $generator->generate();
        $path = $this->path();

        $this->writeEnvFile($path, ['FALLBACK_TOKEN' => $generated->plaintext]);

        if ((bool) $this->option('show')) {
            $this->line('FALLBACK_TOKEN='.$generated->plaintext);
        } else {
            $this->line('Fallback token written for local/bootstrap use. Re-run with --show if you need to display it.');
        }

        return self::SUCCESS;
    }

    private function path(): string
    {
        $path = $this->option('path');

        if (is_string($path) && $path !== '') {
            return $path;
        }

        return $this->laravel->environmentFilePath();
    }
}
