<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\TokenGenerator;
use Illuminate\Console\Command;

final class FallbackTokenGenerateCommand extends Command
{
    protected $signature = 'fallback-token:generate {--show} {--path=}';

    protected $description = 'Generate and store a local fallback token';

    public function handle(TokenGenerator $generator): int
    {
        $generated = $generator->generate();
        $path = $this->path();
        $contents = is_file($path) ? (string) file_get_contents($path) : '';
        $line = 'FALLBACK_TOKEN='.$generated->plaintext;

        if (preg_match('/^FALLBACK_TOKEN=.*$/m', $contents) === 1) {
            $contents = (string) preg_replace('/^FALLBACK_TOKEN=.*$/m', $line, $contents);
        } else {
            $contents = rtrim($contents, "\r\n");
            $contents .= ($contents === '' ? '' : PHP_EOL).$line.PHP_EOL;
        }

        file_put_contents($path, $contents);

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
