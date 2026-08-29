<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * The re-key verb's CLI transport (Console PRD D12) — the same
 * {@see FileConsoleKey} action {@see ManageConsoleKeys} runs, reached
 * with the same two arguments, so the two transports produce the same
 * outcome rather than two implementations of one idea.
 *
 * It takes key material on argv, which every other verb in this package
 * refuses to do — and that is sound HERE and nowhere else: what it takes
 * is a PUBLIC key. D7's CLI rule exists because argv reaches shell
 * history and the process table, which is fatal for a secret and
 * uninteresting for a value the vendor publishes. Nothing about this
 * command's shape should be copied to a verb that handles a secret.
 *
 * `--local` is required, exactly as on the credential verbs: the console
 * keyring lives in THIS app's database and this verb reveals nothing, so
 * there is no cloud-wrapped mode to fall back to. To re-key a remote
 * deployment, call its HTTP contract with an operator credential.
 */
final class ConsoleReKeyCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:console:re-key
        {key_id : The key id (kid) the vendor will name in its assertion footers}
        {public_key : The 32-byte Ed25519 PUBLIC key, hex or unpadded base64url}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'File and activate a console countersigning key without re-onboarding; the outgoing key keeps verifying';

    public function handle(FileConsoleKey $fileConsoleKey): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $keyId = (string) $this->argument('key_id');

        try {
            $delivery = ConsoleKeyDelivery::fromParts($keyId, (string) $this->argument('public_key'));

            $filed = DB::transaction(
                fn (): ConsoleKeyFiled => $fileConsoleKey($delivery, AuditActor::cliOperator()),
            );
        } catch (ConsoleKeyRefused $refused) {
            $fileConsoleKey->recordRefusal($refused, AuditActor::cliOperator(), $keyId);

            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line(sprintf(
            'Console key %s is filed and active as of %s.',
            $filed->key->key_id,
            (string) $filed->key->activated_at?->toRfc3339String(),
        ));

        // The overlap, stated rather than implied: the operator's next
        // step is to confirm the outgoing key still verifies and only
        // then retire it, which is a separate operation.
        $this->line(sprintf(
            'Keys now verifying: %s. Nothing was retired — retire the outgoing key separately, once every assertion minted under it has expired.',
            implode(', ', $filed->activeKeyIds),
        ));

        return self::SUCCESS;
    }
}
