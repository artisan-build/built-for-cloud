<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Subject;

/**
 * The signing half of the pair the package ships (PRD 1.21, SEC-V3-07):
 * produce the `BFC-Signature` header for an outgoing message, signed with
 * the subject's ACTIVE key only.
 *
 * Key selection is the signing-cutover rule stated once: among the
 * subject's live active hmac rows, a row NOT stamped `rotated_at` wins —
 * that is the activated replacement. Between a rotation and its
 * activation the replacement is still PENDING (excluded by status), so
 * the stamped old row keeps signing: the cutover happens exactly at
 * activation, never at rotate. A subject with ONLY pending keys signs
 * nothing, explicitly ({@see HmacSigningRefused} — locked AC 9).
 *
 * The signed string is the canonical envelope ({@see HmacEnvelope});
 * nonce and timestamp are fresh per call. Key material exists only for
 * the duration of the HMAC computation and reaches no log, no event, no
 * return value — the header carries the key ID, never the key.
 */
final class HmacSigner
{
    public function __construct(private readonly HmacKeyring $keyring) {}

    /**
     * Sign a message body for the subject; returns the full
     * `BFC-Signature` header value. The audience always comes from the
     * required `built-for-cloud.hmac.audience` value. The optional
     * argument is retained for source compatibility, but may only confirm
     * that same value; it can never override the deployment boundary.
     */
    public function sign(Subject $subject, string $body, string $eventType, ?string $audience = null): string
    {
        $configuredAudience = $this->configuredAudience($audience);
        $credential = $this->activeSigningKey($subject);

        $envelope = new HmacEnvelope(
            keyId: $credential->id,
            eventType: $eventType,
            timestamp: now()->getTimestamp(),
            nonce: bin2hex(random_bytes(16)),
            audience: $configuredAudience,
        );

        $signature = hash_hmac(
            'sha256',
            $envelope->canonical($body),
            $this->keyring->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version),
        );

        return $envelope->headerValue($signature);
    }

    private function activeSigningKey(Subject $subject): Credential
    {
        $candidates = Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('subject_type', $subject->type->value)
            ->where('subject_ref', $subject->ref)
            ->whereNotNull('secret_ciphertext')
            ->active()
            ->get();

        // Prefer the unstamped (activated replacement) rows; the stamped
        // pool is the between-rotate-and-activate state, where the old
        // key still owns signing.
        $preferred = $candidates->whereNull('rotated_at');
        $pool = $preferred->isNotEmpty() ? $preferred : $candidates;

        /** @var Credential|null $signer */
        $signer = $pool
            ->sortByDesc(fn (Credential $row): string => ($row->activated_at?->toIso8601String() ?? '').'|'.($row->created_at?->toIso8601String() ?? ''))
            ->first();

        if ($signer === null) {
            $pendingKeys = Credential::query()
                ->where('kind', CredentialKind::Hmac->value)
                ->where('subject_type', $subject->type->value)
                ->where('subject_ref', $subject->ref)
                ->where('status', 'pending')
                ->whereNull('revoked_at')
                ->count();

            throw HmacSigningRefused::noActiveKey($subject, $pendingKeys);
        }

        return $signer;
    }

    private function configuredAudience(?string $supplied): string
    {
        $configured = config('built-for-cloud.hmac.audience');

        if (! is_string($configured) || $configured === '') {
            throw HmacSigningRefused::audienceNotConfigured();
        }

        if ($supplied !== null && ! hash_equals($configured, $supplied)) {
            throw HmacSigningRefused::audienceMismatch();
        }

        return $configured;
    }
}
