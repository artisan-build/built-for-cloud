<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\OwnerCredentialMinter;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * Issues the current owner a fresh admin-scoped owner token when it still owns
 * the environment but has lost its copy of the token, which would otherwise be
 * a permanent lockout: claim answers 409 and release is admin-gated.
 *
 * Ownership itself never moves — the owner is whoever it already was — so this
 * is console/database authenticated only and is never exposed over HTTP.
 */
final class OwnershipRemintOwnerTokenCommand extends Command
{
    protected $signature = 'bfc:ownership:remint-owner-token {--execute} {--hash=} {--environment=} {--local}';

    protected $description = 'Mint a replacement admin owner token for the current owner and revoke the previous one';

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, OwnerCredentialMinter $minter): int
    {
        if ((bool) $this->option('execute')) {
            return $this->remintLocally($minter, (string) $this->option('hash'));
        }

        // `--local` (PRD 1.11): owner-token recovery with zero Cloud
        // dependency — generate here, remint here, print once.
        if ((bool) $this->option('local')) {
            $generated = $generator->generate();
            $status = $this->remintLocally($minter, $generated->hash);

            if ($status === self::SUCCESS) {
                $this->line('Save this token - shown once: '.$generated->plaintext);
            }

            return $status;
        }

        $generated = $generator->generate();
        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'bfc:ownership:remint-owner-token --execute --hash='.escapeshellarg($generated->hash));

        $this->line($result['output']);

        if ($result['exitCode'] !== self::SUCCESS) {
            return $result['exitCode'];
        }

        $this->line('Save this token - shown once: '.$generated->plaintext);

        return self::SUCCESS;
    }

    private function remintLocally(OwnerCredentialMinter $minter, string $hash): int
    {
        /** @var int $status */
        $status = DB::transaction(function () use ($minter, $hash): int {
            $ownership = Ownership::query()->lockForUpdate()->first();

            if ($ownership === null || ! $ownership->hasOwner()) {
                $this->error('Ownership is not claimed. Mint a claim token with bfc:ownership:mint-claim instead.');

                return self::FAILURE;
            }

            $previousCredentialId = $ownership->owner_credential_id;
            try {
                $ownerCredential = $minter->mintFromHash($hash);
            } catch (InvalidArgumentException $e) {
                $this->error($e->getMessage());

                return self::FAILURE;
            }

            $this->revokePreviousOwnerCredentials($previousCredentialId, (string) $ownerCredential->getKey());

            $ownership->forceFill([
                'owner_credential_id' => $ownerCredential->getKey(),
            ])->save();

            $this->line('Owner token reminted.');

            return self::SUCCESS;
        });

        return $status;
    }

    private function revokePreviousOwnerCredentials(?string $previousCredentialId, string $currentCredentialId): void
    {
        $now = now();

        if ($previousCredentialId !== null) {
            Credential::query()
                ->whereKey($previousCredentialId)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => $now]);
        }

        Credential::query()
            ->where('kind', CredentialKind::Bearer->value)
            ->where('subject_type', SubjectType::Operator->value)
            ->where('subject_ref', 'owner')
            ->whereKeyNot($currentCredentialId)
            ->active()
            ->update(['revoked_at' => $now]);
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
