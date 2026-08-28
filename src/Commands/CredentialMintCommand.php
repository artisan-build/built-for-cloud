<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Console\Command;

/**
 * The mint verb's CLI transport (PRD 1.0 + 1.6): the same
 * {@see MintCredential} action the HTTP transport runs, against the local
 * database with zero Cloud dependency.
 *
 * D7's CLI rule holds on this surface: the command OUTPUTS the secret —
 * printed exactly once, to the TTY, straight out of the sealed carrier —
 * and accepts no secret input of any kind.
 */
final class CredentialMintCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential:mint
        {subject-type : What a revocation costs: application, installation, user_principal, external_consumer or operator}
        {subject-ref : The subject\'s partition key (tenancy lives here, never in the name)}
        {--kind=bearer : bearer, basic, asymmetric or hmac}
        {--name= : Decorative, freely editable, non-unique label}
        {--abilities= : Comma-separated abilities; omitted grants nothing}
        {--expires= : Credential expiry (ISO-8601). Omitted means NO expiry — never defaulted}
        {--user= : Bind the credential to this app user id}
        {--code-ttl= : Enrollment-code ttl in seconds (asymmetric kind; required, 60–604800)}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Mint a credential into the unified store for a subject';

    public function handle(MintCredential $mint): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $subjectType = SubjectType::tryFrom((string) $this->argument('subject-type'));

        if ($subjectType === null) {
            $this->error('Unknown subject type. One of: '.implode(', ', SubjectType::values()).'.');

            return self::FAILURE;
        }

        // Validation and normalization live in the shared input object and
        // the action, NOT here — the CLI must reject exactly what HTTP
        // rejects (Fix 4: `--code-ttl=60junk` is junk, never 60).
        try {
            $result = $mint(
                new Subject($subjectType, (string) $this->argument('subject-ref')),
                MintOptions::fromInput([
                    'kind' => $this->stringOption('kind'),
                    'name' => $this->stringOption('name'),
                    'abilities' => $this->stringOption('abilities'),
                    'expires_at' => $this->stringOption('expires'),
                    'user_id' => $this->stringOption('user'),
                    'code_ttl_seconds' => $this->stringOption('code-ttl'),
                ]),
                AuditActor::cliOperator(),
            );
        } catch (CredentialVerbRefused|InvalidCredentialInput|RewrapInProgress $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->describe($result);
        $this->revealOnce($result);

        return self::SUCCESS;
    }

    private function describe(MintResult $result): void
    {
        $summary = $result->summary;

        $this->line(sprintf(
            'Credential %s (%s, %s) minted for %s:%s.',
            $summary->id,
            $summary->kind->value,
            $summary->status,
            $summary->subjectType->value,
            $summary->subjectRef,
        ));
    }

    /**
     * The single point of delivery: printing once to the TTY IS the
     * delivery mechanism (D7). The carrier's reveal() throws on any second
     * call, so a second print is structurally impossible.
     */
    private function revealOnce(MintResult $result): void
    {
        switch ($result->delivery) {
            case DeliveryShape::Bearer:
                if ($result->secret !== null) {
                    $this->line('Save this credential - shown once: '.$result->secret->reveal());
                }
                break;
            case DeliveryShape::BasicAuth:
                $this->line('auth.json username: '.(string) $result->basicUsername);

                if ($result->secret !== null) {
                    $this->line('Save this password - shown once: '.$result->secret->reveal());
                }
                break;
            case DeliveryShape::EnrollmentCode:
                if ($result->secret !== null) {
                    $this->line('Enrollment code - shown once: '.$result->secret->reveal());
                }
                break;
            case DeliveryShape::SigningKey:
                $this->line('Signing key id: '.$result->summary->id);

                if ($result->secret !== null) {
                    $this->line('Save this signing key - shown once: '.$result->secret->reveal());
                }

                if ($result->deliveryFingerprint !== null) {
                    $this->line('Delivery fingerprint: '.$result->deliveryFingerprint.' - the receiver quotes this back when confirming installation; activation requires it.');
                }

                $this->line('The key is PENDING: it signs and verifies nothing until bfc:credential:activate cuts it over.');
                break;
            case DeliveryShape::SigningKeyCode:
                if ($result->secret !== null) {
                    $this->line('Claim code - shown once: '.$result->secret->reveal());
                }

                $this->line('Exchanging the code delivers the PENDING signing key and never activates it.');
                break;
            case DeliveryShape::None:
                $this->line('No secret to deliver: it was never ours to hand over.');
                break;
        }
    }
}
