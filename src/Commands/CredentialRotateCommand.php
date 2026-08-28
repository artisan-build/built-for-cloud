<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\RotationResult;
use Illuminate\Console\Command;

/**
 * The rotate verb's CLI transport (PRD 1.0 + 1.7): the same
 * {@see RotateCredential} action the HTTP transport runs. By ID — the
 * primary verb; `--name` is the CLI convenience that resolves the ONE
 * active credential of a name and refuses on ambiguity (D6 point 2).
 *
 * D7's CLI rule holds: the command OUTPUTS the replacement secret — printed
 * exactly once, straight out of the sealed carrier — and accepts no secret
 * input of any kind.
 */
final class CredentialRotateCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:credential:rotate
        {id? : The credential row id to rotate (the primary verb)}
        {--name= : Rotate the ONE active credential of this name; refuses when the name is ambiguous}
        {--emergency : Kill the old credential immediately instead of granting the one-hour grace window}
        {--override : Explicitly authorize a changed replacement (required for --abilities / --expires)}
        {--abilities= : Override the replacement\'s abilities (comma-separated; requires --override)}
        {--expires= : Override the replacement\'s expiry (ISO-8601; requires --override)}
        {--code-ttl= : Enrollment-code ttl in seconds when rotating an asymmetric credential (60–604800)}
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Rotate a unified-store credential: mint the replacement first, retire the old row at grace end';

    public function handle(RotateCredential $rotate): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        $id = $this->argument('id');
        $name = $this->stringOption('name');

        if (is_string($id) === ($name !== null)) {
            $this->error('Pass exactly one target: a credential id (the primary verb), or --name for the single-row name convenience.');

            return self::FAILURE;
        }

        try {
            if ($id === null) {
                $id = $rotate->idForName((string) $name);
            }

            $result = $rotate(
                (string) $id,
                RotateOptions::fromInput([
                    'emergency' => (bool) $this->option('emergency'),
                    'override' => (bool) $this->option('override'),
                    'abilities' => $this->stringOption('abilities'),
                    'expires_at' => $this->stringOption('expires'),
                    'code_ttl_seconds' => $this->stringOption('code-ttl'),
                ]),
                AuditActor::cliOperator(),
            );
        } catch (CredentialVerbRefused|InvalidCredentialInput|RotationRefused|RotationCutoverIncomplete $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        if ($result === null) {
            $this->error("No credential {$id} exists.");

            return self::FAILURE;
        }

        $this->describe($result);
        $this->revealOnce($result);

        return self::SUCCESS;
    }

    private function describe(RotationResult $result): void
    {
        $summary = $result->mint->summary;

        $this->line(sprintf(
            'Credential %s (%s, %s) minted for %s:%s, superseding %s.',
            $summary->id,
            $summary->kind->value,
            $summary->status,
            $summary->subjectType->value,
            $summary->subjectRef,
            $result->supersededId,
        ));

        $this->line((bool) $this->option('emergency')
            ? 'Emergency rotation: the old credential is dead now.'
            : 'The old credential stays resolvable through its grace window (one hour), then dies by its own expiry.');
    }

    /**
     * The single point of delivery (D7): printing once to the TTY IS the
     * delivery. The carrier's reveal() throws on any second call, so a
     * second print is structurally impossible.
     */
    private function revealOnce(RotationResult $result): void
    {
        $mint = $result->mint;

        switch ($mint->delivery) {
            case DeliveryShape::Bearer:
                if ($mint->secret !== null) {
                    $this->line('Save this credential - shown once: '.$mint->secret->reveal());
                }
                break;
            case DeliveryShape::BasicAuth:
                $this->line('auth.json username: '.(string) $mint->basicUsername);

                if ($mint->secret !== null) {
                    $this->line('Save this password - shown once: '.$mint->secret->reveal());
                }
                break;
            case DeliveryShape::EnrollmentCode:
                if ($mint->secret !== null) {
                    $this->line('Enrollment code - shown once: '.$mint->secret->reveal());
                }
                break;
            case DeliveryShape::None:
                $this->line('No secret to deliver: it was never ours to hand over.');
                break;
        }
    }
}
