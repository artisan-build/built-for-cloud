<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyRetired;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * The retirement verb's CLI transport (Console PRD D12) — the same
 * {@see RetireConsoleKey} action {@see ManageConsoleKeys::retire} runs,
 * so the two transports have identical EFFECTS for a caller each has
 * authorized.
 *
 * ## Its authority is HOST ACCESS, and that is not the HTTP gate
 *
 * Stated as plainly as {@see ConsoleReKeyCommand} states it, and for the
 * same reason: `--local` is a mode flag and not an authorization step.
 * **This command performs no credential check of any kind.** Anyone who
 * can run `php artisan` in this application's directory can stop this
 * deployment trusting a console key — and can equally open `tinker` or
 * edit the database to the same effect, which is why this grants no
 * authority host access did not already carry. What it adds is a
 * validated path, the last-active-key decision, and an audit row.
 *
 * The HTTP transport is the one with an authorization model:
 * {@see OperatorAbility::ConsoleKeyWrite}, rate limits, and a uniform
 * refusal. **Nothing here implies the two authorize alike.**
 *
 * ## Why this verb ships on the CLI at all
 *
 * Because the state it repairs can be the state that makes the HTTP
 * transport hard to reach. Retiring a key is the step an operator takes
 * when they believe the outgoing private half is somewhere it should not
 * be, and "mint an operator credential first" is a poor answer to that.
 * Host access is already sufficient to file a key here; refusing to let
 * it end one would have been an asymmetry with nothing behind it.
 *
 * ## `--confirm-last-active-key`
 *
 * Retiring the last key that still verifies ends delegated entry to this
 * deployment. It is permitted, and it is not something to reach by
 * retiring one key too many, so it needs this flag. Without it the
 * command refuses and prints what the flag would do.
 */
final class ConsoleRetireKeyCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:console:retire-key
        {key_id : The key id (kid) to stop trusting}
        {--confirm-last-active-key : Retire it even if it is the last key still verifying, ending delegated entry until a fresh key is filed}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Stop trusting a filed console countersigning key, permanently; other filed keys keep verifying';

    public function handle(RetireConsoleKey $retireConsoleKey): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $keyId = (string) $this->argument('key_id');

        // `cli_operator` — the audit stream's existing name for
        // "authorized by host access", and an honest one: there is no
        // credential here to attribute this to.
        $actor = AuditActor::cliOperator();

        try {
            $retired = DB::transaction(
                fn (): ConsoleKeyRetired => $retireConsoleKey(
                    $keyId,
                    $actor,
                    (bool) $this->option('confirm-last-active-key'),
                ),
            );
        } catch (ConsoleKeyRefused $refused) {
            $retireConsoleKey->recordRefusal($refused, $actor, $keyId);

            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        // The distinction the exit code deliberately does NOT carry: a
        // repeat retirement succeeds, because the state the operator
        // asked for holds. Which call produced it is in the line below
        // and in `retired_at`, not in the status.
        $this->line($retired->newlyRetired
            ? sprintf('Console key %s stopped verifying at %s.', $retired->keyId, (string) $retired->retiredAt?->toRfc3339String())
            : sprintf('Console key %s was ALREADY retired, at %s. Nothing changed.', $retired->keyId, (string) $retired->retiredAt?->toRfc3339String()));

        $this->line($retired->activeKeyIds === []
            ? 'No console key verifies any more: no assertion will verify and no operator can be handed to this deployment until a freshly generated key is filed and activated with bfc:console:re-key.'
            : 'Keys still verifying: '.implode(', ', $retired->activeKeyIds).'.');

        // Say what authorized this, in the transcript an operator keeps.
        $this->line(sprintf(
            'Authorized by HOST ACCESS and audited as %s — this transport has no credential gate; the HTTP verb requires the %s ability.',
            AuditActorType::CliOperator->value,
            OperatorAbility::ConsoleKeyWrite->value,
        ));

        return self::SUCCESS;
    }
}
