<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use Illuminate\Console\Command;

/**
 * The revoke verb's CLI transport (PRD 1.0): the same
 * {@see RevokeCredential} action the HTTP transport runs. By id — the
 * precise verb; exactly this row dies.
 */
final class CredentialRevokeCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential:revoke
        {id : The credential row id to revoke}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Revoke a unified-store credential by id';

    public function handle(RevokeCredential $revoke): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $id = (string) $this->argument('id');

        try {
            $outcome = $revoke($id, AuditActor::cliOperator());
        } catch (CredentialVerbRefused $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        return match ($outcome) {
            RevokeOutcome::NotFound => $this->reportNotFound($id),
            RevokeOutcome::Revoked => $this->report("Revoked credential {$id}."),
            RevokeOutcome::AlreadyDead => $this->report("Credential {$id} was already dead; nothing changed."),
        };
    }

    private function report(string $message): int
    {
        $this->line($message);

        return self::SUCCESS;
    }

    private function reportNotFound(string $id): int
    {
        $this->error("No credential {$id} exists.");

        return self::FAILURE;
    }
}
