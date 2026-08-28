<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\ActivationResult;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Exceptions\ActivationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use Illuminate\Console\Command;

/**
 * The activate verb's CLI transport (PRD 1.21, SEC-V3-01): the same
 * {@see ActivateCredential} action the HTTP transport runs. This is the
 * operator's half of the hmac rotation dance —
 * `credential:rotate <id>` → deliver → receiver installs and confirms
 * out-of-band → `credential:activate <id>` — and it outputs NO secret:
 * activation reveals nothing, because the key was already delivered
 * (D7's CLI rule holds trivially — nothing secret in, nothing secret
 * out).
 */
final class CredentialActivateCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential:activate
        {id : The pending hmac credential to cut signing over to}
        {--fingerprint= : The delivery fingerprint the receiver confirmed installed (rides every signing-key delivery); activation binds to that exact delivery}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Cut a delivered pending hmac signing key over to active; a superseded key retires into its grace window';

    public function handle(ActivateCredential $activate): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $id = (string) $this->argument('id');

        try {
            $result = $activate($id, $this->stringOption('fingerprint'), AuditActor::cliOperator());
        } catch (CredentialVerbRefused|ActivationRefused|InvalidCredentialInput|RewrapInProgress|RotationCutoverIncomplete $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        if ($result === null) {
            $this->error("No credential {$id} exists.");

            return self::FAILURE;
        }

        $this->describe($result);

        return self::SUCCESS;
    }

    private function describe(ActivationResult $result): void
    {
        $summary = $result->summary;

        $this->line(sprintf(
            'Credential %s (%s, %s) is now the active signing key for %s:%s.',
            $summary->id,
            $summary->kind->value,
            $summary->status,
            $summary->subjectType->value,
            $summary->subjectRef,
        ));

        if ($result->supersededId !== null) {
            $this->line(sprintf(
                'Superseded key %s keeps verifying through its grace window (until %s at the latest), then dies by its own expiry.',
                $result->supersededId,
                (string) $result->graceEndsAt?->toIso8601String(),
            ));
        }
    }
}
