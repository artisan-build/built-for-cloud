<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
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

    public function handle(CloudCommandRunner $runner, TokenGenerator $generator, TokenRegistry $registry): int
    {
        if ((bool) $this->option('execute')) {
            return $this->remintLocally($registry, (string) $this->option('hash'));
        }

        // `--local` (PRD 1.11): owner-token recovery with zero Cloud
        // dependency — generate here, remint here, print once.
        if ((bool) $this->option('local')) {
            $generated = $generator->generate();
            $status = $this->remintLocally($registry, $generated->hash);

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

    private function remintLocally(TokenRegistry $registry, string $hash): int
    {
        /** @var int $status */
        $status = DB::transaction(function () use ($registry, $hash): int {
            $ownership = Ownership::query()->lockForUpdate()->first();

            if ($ownership === null || $ownership->owner_token_id === null) {
                $this->error('Ownership is not claimed. Mint a claim token with bfc:ownership:mint-claim instead.');

                return self::FAILURE;
            }

            $previousTokenId = $ownership->owner_token_id;

            try {
                $ownerToken = $registry->store('owner', $hash, abilities: [Scope::Admin->value]);
            } catch (InvalidArgumentException $e) {
                $this->error($e->getMessage());

                return self::FAILURE;
            }

            $this->revokePreviousOwnerTokens($previousTokenId, (string) $ownerToken->getKey());

            $ownership->forceFill(['owner_token_id' => $ownerToken->getKey()])->save();

            $this->line('Owner token reminted.');

            return self::SUCCESS;
        });

        return $status;
    }

    private function revokePreviousOwnerTokens(string $previousTokenId, string $currentTokenId): void
    {
        $now = now();

        ApiToken::query()
            ->where(function (Builder $query) use ($previousTokenId): void {
                $query->where('name', 'owner')
                    ->orWhere((new ApiToken)->getKeyName(), $previousTokenId);
            })
            ->whereKeyNot($currentTokenId)
            ->resolvable()
            ->update([
                'expires_at' => $now,
                'revoked_at' => $now,
            ]);
    }

    private function stringOption(string $key): ?string
    {
        $value = $this->option($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
