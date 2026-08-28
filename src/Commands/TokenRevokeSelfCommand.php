<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * The emergency revoke path the HOLDER can reach (PRD 1.3, v2.1: the
 * surviving case is the hitch-minted MCP token, whose holder otherwise
 * cannot revoke without the operator): present the credential itself, and
 * exactly that credential dies.
 *
 * The secret arrives over STDIN (piped) or a hidden prompt — NEVER as an
 * argument (D7's CLI rule: argv reaches shell history and the process
 * table). The command never echoes or logs it; on any failure it reports
 * only that no live credential matched.
 *
 * The HTTP variant of holder self-revocation rides the two-transport PR.
 */
final class TokenRevokeSelfCommand extends Command
{
    protected $signature = 'bfc:token:revoke-self {secret? : REFUSED — pipe the credential on STDIN or use the prompt, never argv}';

    protected $description = 'Revoke the credential presented on STDIN — the holder\'s emergency revoke';

    public function handle(LifecycleEventRecorder $recorder): int
    {
        if ($this->argument('secret') !== null) {
            // Refuse without echoing: the value is already in argv, but
            // repeating it in output would widen the exposure.
            $this->error('A credential is never passed as an argument — it lands in shell history and the process table. Pipe it on STDIN instead.');

            return self::FAILURE;
        }

        $secret = $this->presentedSecret();

        if ($secret === null || $secret === '') {
            $this->error('No credential was presented.');

            return self::FAILURE;
        }

        // Deliberately NOT TokenRegistry::resolve(): presenting a credential
        // for revocation is not a use, and must not trigger the first-use
        // burn or bump usage counters. The fallback token has no row and
        // cannot be self-revoked; it dies by deletion from the environment.
        $revoked = DB::transaction(function () use ($recorder, $secret): ?ApiToken {
            /** @var ApiToken|null $token */
            $token = ApiToken::query()
                ->where('token_hash', hash('sha256', $secret))
                ->resolvable()
                ->whereNull('revoked_at')
                ->lockForUpdate()
                ->first();

            if ($token === null) {
                return null;
            }

            $now = now();

            $token->forceFill([
                'expires_at' => $now,
                'revoked_at' => $now,
            ])->save();

            $recorder->record(
                event: LifecycleEventType::Revoked,
                credentialId: (string) $token->getKey(),
                actor: AuditActor::credentialHolder((string) $token->getKey()),
                reason: AuditReason::HolderRequest,
            );

            return $token;
        });

        if ($revoked === null) {
            $this->error('No live credential matches the presented secret.');

            return self::FAILURE;
        }

        $this->line("Revoked credential {$revoked->getKey()} ({$revoked->name}).");

        return self::SUCCESS;
    }

    /**
     * Piped STDIN first; a hidden prompt when STDIN is a TTY. Both paths
     * keep the secret out of argv.
     */
    private function presentedSecret(): ?string
    {
        if (defined('STDIN') && ! stream_isatty(STDIN)) {
            $line = fgets(STDIN);

            if (is_string($line) && trim($line) !== '') {
                return trim($line);
            }
        }

        $answer = $this->secret('Present the credential to revoke');

        return is_string($answer) ? trim($answer) : null;
    }
}
