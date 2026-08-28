<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Commands\Concerns\WritesInstallEnv;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use Illuminate\Console\Command;

/**
 * @deprecated PRD 1.20 — FALLBACK_TOKEN retirement. The install path mints
 * a real, revocable, operator-subject credential instead
 * ({@see InstallOperatorCredentialCommand}); an env pseudo-credential can
 * never be revoked, audited, or attributed. The command (and the
 * `fallback_token` config it feeds) stays functional because live 0.4.x
 * apps still carry fallbacks — and the fail-closed MCP gate remains the
 * belt while any do — but nothing in the framework's own paths creates or
 * reads one any more, and a later major removes it.
 */
final class FallbackTokenGenerateCommand extends Command
{
    use WritesInstallEnv;

    protected $signature = 'fallback-token:generate {--show} {--path=}';

    protected $description = 'DEPRECATED: generate and store a local fallback token (use bfc:install:operator-credential)';

    public function handle(TokenGenerator $generator): int
    {
        $this->warn(
            'DEPRECATED: fallback tokens are retired in favour of a real operator credential. '
            .'Run bfc:install:operator-credential instead; existing fallbacks keep working until removed.',
        );

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
