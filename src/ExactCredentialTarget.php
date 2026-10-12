<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;

/**
 * The identity a caller believes it is operating on, re-proved INSIDE the
 * package's locked boundary.
 *
 * A consumer that pre-selects a credential — "the bearer credential whose
 * purpose is consumption and whose subject is installation `app-a`" — holds
 * that answer only until its own query returns. Between that read and the
 * verb's write, the row's IDENTITY dimensions can change: its purpose, its
 * subject binding, its kind, its ownership. The verb then operates on an id
 * that no longer means what the caller selected, and nothing refuses, because
 * the id is still the id.
 *
 * The package's own rechecks under the lock cover the MUTABLE LIFECYCLE
 * conditions it owns (pending, revoked, expired, already-rotated). They
 * deliberately say nothing about identity, since identity is the caller's
 * selection, not the package's state. This object is how the caller hands
 * that selection over as DATA the package enforces: {@see RotateOptions}
 * carries it, and {@see RotateCredential} re-evaluates it against the row
 * it has locked, before anything is consumed or minted.
 *
 * `purpose` and `subject` are required — a predicate that pins neither is
 * not a predicate — while `kind` and `ownership` are pinned only when
 * supplied. A dimension left out is NOT asserted; it is the caller saying
 * it does not care, exactly as an absent dimension on {@see RotateOptions}
 * means "preserve".
 *
 * A mismatch is {@see RotationRefused}, not a silent no-op: the caller
 * asked to rotate a specific thing, and the thing it asked about is gone.
 */
final readonly class ExactCredentialTarget
{
    public function __construct(
        public CredentialPurpose $purpose,
        public Subject $subject,
        public ?CredentialKind $kind = null,
        public ?CredentialOwnership $ownership = null,
    ) {}

    /**
     * Every pinned dimension on which the row disagrees with this
     * predicate, by NAME. Names only, never values: the diagnostic says
     * which part of the caller's belief broke without publishing what the
     * row now holds.
     *
     * @return list<string>
     */
    public function mismatchesOf(Credential $credential): array
    {
        $mismatches = [];

        if ($credential->purpose !== $this->purpose) {
            $mismatches[] = 'purpose';
        }

        if ($credential->subject_type !== $this->subject->type || $credential->subject_ref !== $this->subject->ref) {
            $mismatches[] = 'subject';
        }

        if ($this->kind !== null && $credential->kind !== $this->kind) {
            $mismatches[] = 'kind';
        }

        if ($this->ownership !== null && $credential->ownership() !== $this->ownership) {
            $mismatches[] = 'ownership';
        }

        return $mismatches;
    }

    public function matches(Credential $credential): bool
    {
        return $this->mismatchesOf($credential) === [];
    }

    /**
     * Called by the verb with a row it holds a lock on — which is the
     * whole point: the answer is true of the row AT THE LOCK, so no
     * retarget can land between the check and the write.
     */
    public function assertMatches(Credential $credential): void
    {
        $mismatches = $this->mismatchesOf($credential);

        if ($mismatches !== []) {
            throw RotationRefused::targetNoLongerMatches($credential->id, $mismatches);
        }
    }
}
