<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

final class TokenCreateCommand extends Command
{
    protected $signature = 'token:create {name} {--execute} {--hash=} {--environment=} {--local} {--abilities=}';

    protected $description = 'Create a Built for Cloud API token';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        $name = (string) $this->argument('name');
        $abilities = $this->abilitiesOption();

        if ((bool) $this->option('execute')) {
            $this->storeToken($registry, $name, (string) $this->option('hash'), $abilities);
            $this->line("Token {$name} stored.");

            return self::SUCCESS;
        }

        $generated = $generator->generate();

        // PRD 1.11: the same command, zero Cloud dependency — the plaintext
        // never leaves this process and the hash lands in the local store.
        if ((bool) $this->option('local')) {
            $this->storeToken($registry, $name, $generated->hash, $abilities);
            $this->line('Save this token - shown once: '.$generated->plaintext);

            return self::SUCCESS;
        }

        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'token:create '.$this->quote($name).' --execute --hash='.$generated->hash.$this->remoteAbilitiesOption($abilities));

        $this->line($result['output']);

        if ($result['exitCode'] !== self::SUCCESS) {
            return $result['exitCode'];
        }

        $this->line('Save this token - shown once: '.$generated->plaintext);

        return self::SUCCESS;
    }

    /**
     * The store plus its `issued` audit event, one transaction (PRD 1.16 —
     * closing the mint-path gap the audit release noted): a stored token
     * whose issuance the stream never saw would make the stream fiction.
     *
     * @param  list<string>  $abilities
     */
    private function storeToken(TokenRegistry $registry, string $name, string $hash, array $abilities): void
    {
        DB::transaction(function () use ($registry, $name, $hash, $abilities): void {
            $token = $registry->store($name, $hash, abilities: $abilities);

            app(LifecycleEventRecorder::class)->record(
                event: LifecycleEventType::Issued,
                credentialId: (string) $token->getKey(),
                actor: AuditActor::cliOperator(),
            );
        });
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

    /**
     * @return list<string>
     */
    private function abilitiesOption(): array
    {
        $value = $this->stringOption('abilities');

        if ($value === null) {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (string $ability): string => trim($ability),
            explode(',', $value),
        ), static fn (string $ability): bool => $ability !== ''));
    }

    /**
     * @param  list<string>  $abilities
     */
    private function remoteAbilitiesOption(array $abilities): string
    {
        if ($abilities === []) {
            return '';
        }

        return ' --abilities='.$this->quote(implode(',', $abilities));
    }
}
