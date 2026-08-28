<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\IssueInvitation;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\IntegrationEventContention;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\InvitationOptions;
use Illuminate\Console\Command;

/**
 * The invite verb's CLI transport (PRD 1.13): the same
 * {@see IssueInvitation} action the HTTP transport runs, against the local
 * database with zero Cloud dependency.
 *
 * D7's CLI rule holds: the command OUTPUTS the invitation code — printed
 * exactly once, to the TTY, straight out of the sealed carrier — and
 * accepts no secret input of any kind.
 */
final class InvitationIssueCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:invitation:issue
        {--email= : Address the invitation to this recipient; omitted issues an OPEN code}
        {--ttl= : Invitation ttl in seconds (required, 60–604800) — never defaulted}
        {--invited-by= : The inviter\'s reference (nullable string, up to 64 characters)}
        {--role= : Stored on the invitation for the accept hook; never interpreted by the package}
        {--integration-namespace= : SEC-V3-05 integration event: the namespace (all four event options together, or none)}
        {--event-id= : SEC-V3-05 integration event: the stable event id}
        {--entitlement-version= : SEC-V3-05 integration event: the monotonic entitlement version}
        {--external-subject= : SEC-V3-05 integration event: the external subject the version gate keys on}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Issue an invitation — addressed or open, human- or integration-driven';

    public function handle(IssueInvitation $issue): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        try {
            $result = $issue(
                InvitationOptions::fromInput([
                    'email' => $this->stringOption('email'),
                    'ttl_seconds' => $this->stringOption('ttl'),
                    'invited_by' => $this->stringOption('invited-by'),
                    'role' => $this->stringOption('role'),
                    'integration_namespace' => $this->stringOption('integration-namespace'),
                    'event_id' => $this->stringOption('event-id'),
                    'entitlement_version' => $this->stringOption('entitlement-version'),
                    'external_subject' => $this->stringOption('external-subject'),
                ]),
                AuditActor::cliOperator(),
            );
        } catch (CredentialVerbRefused|IntegrationEventContention|InvalidCredentialInput $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        if ($result->invitationId === null) {
            // The gate's acknowledged-and-ignored (or replayed) answer:
            // nothing was issued and there is no code to reveal.
            $this->line('Invitation event acknowledged.');

            return self::SUCCESS;
        }

        $this->line(sprintf(
            'Invitation %s issued%s.',
            $result->invitationId,
            $result->email !== null ? ' for '.$result->email : ' (open)',
        ));

        if ($result->code !== null) {
            // The single point of delivery: printing once to the TTY IS
            // the delivery (D7); the carrier throws on any second call.
            $this->line('Save this invitation code - shown once: '.$result->code->reveal());
        }

        return self::SUCCESS;
    }
}
