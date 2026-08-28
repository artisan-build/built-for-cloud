<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Console\Command;

/**
 * The installer mint (PRD 1.20): install scaffolds run this instead of
 * generating a `FALLBACK_TOKEN`. It mints a REAL, revocable,
 * operator-subject credential through the same `--local` mint action every
 * transport uses — in-process, direct database, zero Cloud dependency —
 * and prints the secret exactly once to the TTY (D7). Nothing is written
 * to the environment file, and nothing on this path reads or writes the
 * fallback config.
 *
 * No expiry, deliberately: an operational control-plane credential with a
 * clock on it is a scheduled outage (GATE-3); revocation-on-event is the
 * intended end of its life, and `bfc:credential:revoke` reaches it.
 */
final class InstallOperatorCredentialCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:install:operator-credential
        {--ref=installer : The operator subject\'s ref (each control plane its own)}
        {--name= : Decorative label for the row}
        {--abilities=admin : Comma-separated abilities for the operator credential}';

    protected $description = 'Mint the install-time operator credential (replaces FALLBACK_TOKEN)';

    public function handle(MintCredential $mint): int
    {
        try {
            $result = $mint(
                new Subject(SubjectType::Operator, (string) $this->option('ref')),
                new MintOptions(
                    kind: CredentialKind::Bearer,
                    name: $this->stringOption('name'),
                    abilities: $this->abilitiesOption() ?? [Scope::Admin->value],
                ),
                AuditActor::cliOperator(),
            );
        } catch (CredentialVerbRefused $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line(sprintf(
            'Operator credential %s minted for operator:%s.',
            $result->summary->id,
            $result->summary->subjectRef,
        ));

        if ($result->secret !== null) {
            $this->line('Save this operator credential - shown once: '.$result->secret->reveal());
        }

        return self::SUCCESS;
    }
}
