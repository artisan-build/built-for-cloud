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
        {--override : Explicitly request a changed replacement (required for the override options below)}
        {--abilities= : Override the replacement\'s abilities (comma-separated; requires --override)}
        {--clear-abilities : Override the replacement to NO abilities (requires --override)}
        {--expires= : Override the replacement\'s expiry (ISO-8601; requires --override)}
        {--clear-expiry : Override the replacement to NO expiry (requires --override)}
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

        $input = $this->overrideAwareInput();

        if ($input === null) {
            return self::FAILURE;
        }

        try {
            if ($id === null) {
                $id = $rotate->idForName((string) $name);
            }

            $result = $rotate((string) $id, RotateOptions::fromInput($input), AuditActor::cliOperator());
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

    /**
     * The shared-input array, with PRESENCE meaning what it means on the
     * HTTP transport (Fix 3): a key appears exactly when the caller chose
     * that dimension. `--abilities=`/`--expires=` provide a value; the
     * `--clear-*` forms provide the dimension as EXPLICITLY NONE (the JSON
     * transport's explicit null / empty list); passing neither leaves the
     * key absent, which always means "preserve the source's". Null on
     * conflicting spellings of one dimension.
     *
     * @return array<string, mixed>|null
     */
    private function overrideAwareInput(): ?array
    {
        $input = [
            'emergency' => (bool) $this->option('emergency'),
            'override' => (bool) $this->option('override'),
            'code_ttl_seconds' => $this->stringOption('code-ttl'),
        ];

        $abilities = $this->stringOption('abilities');

        if ((bool) $this->option('clear-abilities')) {
            if ($abilities !== null) {
                $this->error('Pass --abilities or --clear-abilities, not both.');

                return null;
            }

            $input['abilities'] = [];
        } elseif ($abilities !== null) {
            $input['abilities'] = $abilities;
        }

        $expires = $this->stringOption('expires');

        if ((bool) $this->option('clear-expiry')) {
            if ($expires !== null) {
                $this->error('Pass --expires or --clear-expiry, not both.');

                return null;
            }

            $input['expires_at'] = null;
        } elseif ($expires !== null) {
            $input['expires_at'] = $expires;
        }

        return $input;
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
