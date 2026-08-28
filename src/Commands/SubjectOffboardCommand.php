<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\IntegrationEventContention;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use Illuminate\Console\Command;

/**
 * The offboard verb's CLI transport (PRD 1.15): the same
 * {@see OffboardSubject} action the HTTP transport runs, against the
 * local database with zero Cloud dependency. Full account containment in
 * one command; idempotent, so re-running it is always safe.
 */
final class SubjectOffboardCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:subject:offboard
        {subject_type? : The subject type (required on the direct path; derived from --external-subject on the integration path)}
        {subject_ref? : The subject ref — the tenant partition key a revocation costs (required on the direct path)}
        {--integration-namespace= : SEC-V3-05 integration event: the namespace (all four event options together, or none)}
        {--event-id= : SEC-V3-05 integration event: the stable event id}
        {--entitlement-version= : SEC-V3-05 integration event: the monotonic entitlement version}
        {--external-subject= : SEC-V3-05 integration event: the external subject the version gate keys on}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Offboard a subject: full account containment (PRD 1.15)';

    public function handle(OffboardSubject $offboard): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        try {
            $result = $offboard(
                OffboardOptions::fromInput([
                    'subject_type' => $this->argument('subject_type'),
                    'subject_ref' => $this->argument('subject_ref'),
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

        if ($result->acknowledged) {
            // The gate's uniform answer, matching the HTTP transport:
            // applied, ignored-older, and replayed are indistinguishable.
            $this->line('Offboard event acknowledged.');

            return self::SUCCESS;
        }

        $this->line(sprintf(
            'Subject %s: %d credential(s) revoked, %d claim code(s) consumed, %d invitation(s) canceled, %d reset token(s) deleted, %d session(s) deleted, %d user(s) deactivated.',
            $result->applied ? 'offboarded' : 'already offboarded',
            $result->revokedCredentials,
            $result->consumedCodes,
            $result->canceledInvitations,
            $result->deletedResetTokens,
            $result->deletedSessions,
            $result->deactivatedUsers,
        ));

        return self::SUCCESS;
    }
}
