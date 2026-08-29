<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\FileConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyDelivery;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyFiled;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Console\Input\StreamableInputInterface;

/**
 * The re-key verb's CLI transport (Console PRD D12) — the same
 * {@see FileConsoleKey} action {@see ManageConsoleKeys} runs, so the two
 * transports have identical EFFECTS for a caller each has authorized.
 *
 * ## Its authority is HOST ACCESS, and that is not the HTTP gate
 *
 * State this plainly because an earlier revision did not, and a reader
 * could have taken `--local` for an authorization step. It is not: it is
 * a mode flag. **This command performs no credential check of any kind.**
 * Anyone who can run `php artisan` in this application's directory can
 * file a console countersigning key and thereby install a standing
 * authority to enter this deployment as a delegated admin.
 *
 * That is deliberate, and it is the repo's existing model rather than a
 * new one: `bfc:create-admin` already treats host access as operator
 * authority and creates a full admin user from the same shell. Anyone
 * who can run artisan can also open `tinker` and write the keyring row
 * directly, or edit the database. This command therefore grants no
 * authority that host access did not already carry — what it adds is a
 * validated path and an audit row, both of which the tinker route lacks.
 *
 * Where the `create-admin` analogy is imperfect, said out loud: an admin
 * USER is a row an operator can see and delete, scoped to this app; a
 * console key is a trust root for an EXTERNAL issuer, usable repeatedly,
 * from anywhere, by whoever holds the private half, until someone
 * retires it. The blast radius is more durable. It does not change the
 * conclusion — host access already permits arbitrary database writes —
 * but it is the reason this docblock refuses to call the two transports
 * equivalently authorized.
 *
 * The HTTP transport is the one with an authorization model:
 * {@see OperatorAbility::ConsoleKeyWrite}, rate limits, and a uniform
 * refusal. **Nothing here implies the two authorize alike.** An operator
 * who wants key custody gated by credential rather than by shell should
 * turn off the `commands` surface (PRD 1.14) and use the route.
 *
 * ## Key material comes from STDIN, never argv
 *
 * argv lands in shell history, in `ps` output, and in any process
 * accounting the host keeps. The material here is a PUBLIC key, so
 * secrecy is not the concern — SUBSTITUTION is: a key id and its
 * material sitting in a shared host's history is a ready-made recipe for
 * someone to replay, and a value visible in `ps` is a value an
 * unprivileged local process can watch for. Reading it from stdin keeps
 * it out of both. It is not hidden on screen, which is correct: echoing
 * a public key leaks nothing.
 *
 * `--local` is required, exactly as on the credential verbs: the console
 * keyring lives in THIS app's database and this verb reveals nothing, so
 * there is no cloud-wrapped mode to fall back to.
 */
final class ConsoleReKeyCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:console:re-key
        {key_id : The key id (kid) the vendor will name in its assertion footers}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'File and activate a console countersigning key from stdin, without re-onboarding; the outgoing key keeps verifying';

    public function handle(FileConsoleKey $fileConsoleKey): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $keyId = (string) $this->argument('key_id');

        // The actor is `cli_operator` — the audit stream's existing name
        // for "authorized by host access", and an honest one: there is no
        // credential here to attribute this to.
        $actor = AuditActor::cliOperator();

        $publicKey = $this->readPublicKey();

        if ($publicKey === null) {
            $this->error('Pipe the 32-byte Ed25519 PUBLIC key (hex or unpadded base64url) into this command on stdin; it is deliberately not an argument.');

            return self::FAILURE;
        }

        try {
            $delivery = ConsoleKeyDelivery::fromParts($keyId, $publicKey);

            $filed = DB::transaction(
                fn (): ConsoleKeyFiled => $fileConsoleKey($delivery, $actor),
            );
        } catch (ConsoleKeyRefused $refused) {
            $fileConsoleKey->recordRefusal($refused, $actor, $keyId);

            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line(sprintf(
            'Console key %s is filed and active as of %s.',
            $filed->keyId,
            (string) $filed->activatedAt?->toRfc3339String(),
        ));

        // The overlap, stated rather than implied: the operator's next
        // step is to confirm the outgoing key still verifies and only
        // then retire it, which is a separate operation.
        $this->line(sprintf(
            'Keys now verifying: %s. Nothing was retired — retire the outgoing key separately, once every assertion minted under it has expired.',
            implode(', ', $filed->activeKeyIds),
        ));

        // Say what authorized this, in the transcript an operator keeps.
        $this->line(sprintf(
            'Authorized by HOST ACCESS and audited as %s — this transport has no credential gate; the HTTP verb requires the %s ability.',
            AuditActorType::CliOperator->value,
            OperatorAbility::ConsoleKeyWrite->value,
        ));

        return self::SUCCESS;
    }

    /**
     * One line of key material off the command's input stream.
     *
     * The stream is taken from the input object when it exposes one
     * ({@see StreamableInputInterface} — what `ArgvInput` is, and what
     * lets a test hand this command a memory stream), falling back to
     * the process's own `STDIN`. Whitespace is trimmed, because a piped
     * line carries a newline and an operator's paste may carry a space;
     * neither is part of a key.
     *
     * Returns null when nothing readable arrived, which the caller turns
     * into a refusal rather than an empty-string delivery.
     */
    private function readPublicKey(): ?string
    {
        $stream = $this->input instanceof StreamableInputInterface ? $this->input->getStream() : null;

        if (! is_resource($stream)) {
            $stream = defined('STDIN') ? STDIN : null;
        }

        if (! is_resource($stream)) {
            return null;
        }

        $line = fgets($stream);

        if ($line === false) {
            return null;
        }

        $line = trim($line);

        return $line === '' ? null : $line;
    }
}
