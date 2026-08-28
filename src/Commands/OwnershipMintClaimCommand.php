<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * Re-mints the one-time ownership claim token an unclaimed environment needs
 * when the plaintext minted at migrate time is no longer recoverable.
 *
 * Driver mode generates the token locally and sends only its hash to the target
 * environment; `--execute` is the half that runs there (and is what you reach
 * for directly via `cloud command:run`).
 */
final class OwnershipMintClaimCommand extends Command
{
    protected $signature = 'bfc:ownership:mint-claim {--execute} {--hash=} {--environment=} {--local}';

    protected $description = 'Mint a pending ownership claim token for an unclaimed environment';

    public function handle(CloudCommandRunner $runner, OwnershipClaimMinter $minter): int
    {
        if ((bool) $this->option('execute')) {
            return $this->mintLocally($minter, (string) $this->option('hash'));
        }

        // `--local` (PRD 1.11): the off-Cloud owner-recovery path without
        // computing a sha256 by hand — generate here, mint here, print once.
        if ((bool) $this->option('local')) {
            $generated = $minter->generate();
            $status = $this->mintLocally($minter, $generated->hash);

            if ($status === self::SUCCESS) {
                $this->line('Save this claim token - shown once: '.$generated->plaintext);
            }

            return $status;
        }

        $generated = $minter->generate();
        $environment = $runner->resolveEnvironment($this->stringOption('environment'));
        $result = $runner->run($environment, 'bfc:ownership:mint-claim --execute --hash='.escapeshellarg($generated->hash));

        $this->line($result['output']);

        if ($result['exitCode'] !== self::SUCCESS) {
            return $result['exitCode'];
        }

        $this->line('Save this claim token - shown once: '.$generated->plaintext);

        return self::SUCCESS;
    }

    private function mintLocally(OwnershipClaimMinter $minter, string $hash): int
    {
        /** @var int $status */
        $status = DB::transaction(function () use ($minter, $hash): int {
            $ownership = Ownership::query()->lockForUpdate()->first();

            if ($ownership !== null && $ownership->owner_token_id !== null) {
                $this->error('Ownership is already claimed. Refusing to mint a claim token; use the owner token to release ownership instead.');

                return self::FAILURE;
            }

            try {
                $minter->mintFromHash($hash);
            } catch (InvalidArgumentException $e) {
                $this->error($e->getMessage());

                return self::FAILURE;
            }

            $this->line('Ownership claim minted.');

            return self::SUCCESS;
        });

        return $status;
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
