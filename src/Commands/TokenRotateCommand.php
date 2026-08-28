<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;

/**
 * The legacy `api_tokens` rotation. Name-based here for CLI compatibility,
 * with D6's corrected semantics underneath: the registry refuses whenever
 * more than one resolvable row shares the name (rotate by id instead —
 * `POST /api/credentials/id/{id}/rotate`), and the replacement inherits the
 * source's exact abilities, subject binding and remaining expiry.
 */
final class TokenRotateCommand extends Command
{
    protected $signature = 'token:rotate {name} {--emergency} {--execute} {--hash=} {--environment=} {--local}';

    protected $description = 'Rotate a Built for Cloud API token';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');
        $emergency = (bool) $this->option('emergency');

        if ((bool) $this->option('execute')) {
            if (! $this->rotateLocally($registry, $name, (string) $this->option('hash'), $emergency)) {
                return self::FAILURE;
            }

            return self::SUCCESS;
        }

        $generated = $generator->generate();

        // `--local` (PRD 1.11): the legacy rotation, run against the local
        // database with zero Cloud dependency — transport plumbing only.
        // The unified store's verb is `bfc:credential:rotate`.
        if ((bool) $this->option('local')) {
            if (! $this->rotateLocally($registry, $name, $generated->hash, $emergency)) {
                return self::FAILURE;
            }

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

    /**
     * The shared write half of the --execute and --local paths: a refusal
     * (ambiguous name, nothing to rotate) or an incomplete cutover becomes
     * a clean failure exit carrying the one shared error message — never a
     * stack trace, never a secret.
     */
    private function rotateLocally(TokenRegistry $registry, string $name, string $hash, bool $emergency): bool
    {
        try {
            $registry->rotate($name, $hash, $emergency, AuditActor::cliOperator());
        } catch (RotationRefused|RotationCutoverIncomplete $failure) {
            $this->error($failure->getMessage());

            return false;
        }

        $this->line($emergency ? "Token {$name} rotated with emergency expiry." : "Token {$name} rotated with one hour grace.");

        return true;
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
