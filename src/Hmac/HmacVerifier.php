<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Support\Facades\Cache;

/**
 * The verifying half of the pair (PRD 1.21, SEC-V3-07). The candidate key
 * is selected on **(server-derived subject, key id, active-or-in-grace)**
 * — the untrusted header's key id narrows WITHIN the subject the server
 * already derived, and can never pick a row across subjects (locked
 * AC 8). A pending key is not in the selection at all: it verifies
 * nothing until activated. An in-grace superseded key (status active,
 * grace-bounded expiry) still verifies — that is what makes hmac
 * rotation make-before-break — and stops at grace end by its own expiry.
 *
 * What it rejects, in a deliberate order:
 * 1. a malformed header (anchored parse, {@see HmacEnvelope::parse()});
 * 2. any claimed algorithm but `hmac-sha256` — pinned, no negotiation;
 * 3. the wrong audience;
 * 4. a stale timestamp: |now − ts| beyond the configured tolerance
 *    (`built-for-cloud.hmac.timestamp_tolerance_seconds`, default 300);
 * 5. a key-selection miss — unknown id, another subject's id, a pending
 *    key, a dead key: ONE indistinct answer, no oracle;
 * 6. a signature that does not match the canonical envelope
 *    (constant-time compare);
 * 7. a replayed nonce. The nonce is consumed ONLY AFTER the signature
 *    verified — consuming earlier would let an attacker burn a victim's
 *    nonce with a garbage signature. Storage is the bounded default
 *    cache: one entry per (key id, nonce), TTL = 2× the timestamp
 *    tolerance, which provably covers the whole acceptance window — a
 *    message first verified at V satisfies V ≥ ts − tolerance, so any
 *    replay after the entry expires at V + 2×tolerance ≥ ts + tolerance
 *    is already stale by rule 4.
 */
final class HmacVerifier
{
    public function __construct(private readonly HmacKeyring $keyring) {}

    /**
     * Verify a presented `BFC-Signature` header against the message body
     * for a SERVER-DERIVED subject. Returns the credential that verified
     * (stamping its `last_used_at`); throws {@see HmacVerificationFailed}
     * otherwise.
     */
    public function verify(Subject $subject, string $header, string $body, ?string $audience = null): Credential
    {
        [$envelope, $claimedAlgorithm, $signature] = HmacEnvelope::parse($header);

        if ($claimedAlgorithm !== HmacEnvelope::ALGORITHM) {
            throw HmacVerificationFailed::algorithmRejected($claimedAlgorithm);
        }

        $expectedAudience = $audience ?? $this->defaultAudience();

        if (! hash_equals($expectedAudience, $envelope->audience)) {
            throw HmacVerificationFailed::wrongAudience();
        }

        $tolerance = $this->timestampTolerance();

        if (abs(now()->getTimestamp() - $envelope->timestamp) > $tolerance) {
            throw HmacVerificationFailed::staleTimestamp($tolerance);
        }

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('subject_type', $subject->type->value)
            ->where('subject_ref', $subject->ref)
            ->whereKey($envelope->keyId)
            ->whereNotNull('secret_ciphertext')
            ->active()
            ->first();

        if ($credential === null) {
            throw HmacVerificationFailed::unusableKey();
        }

        $expected = hash_hmac(
            'sha256',
            $envelope->canonical($body),
            $this->keyring->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version),
        );

        if (! hash_equals($expected, $signature)) {
            throw HmacVerificationFailed::invalidSignature();
        }

        $nonceKey = 'bfc:hmac:nonce:'.hash('sha256', $envelope->keyId.'|'.$envelope->nonce);

        if (! Cache::add($nonceKey, 1, $tolerance * 2)) {
            throw HmacVerificationFailed::replayedNonce();
        }

        Credential::query()->whereKey($credential->id)->update(['last_used_at' => now()]);

        return $credential;
    }

    private function timestampTolerance(): int
    {
        $tolerance = config('built-for-cloud.hmac.timestamp_tolerance_seconds', 300);

        return is_numeric($tolerance) && (int) $tolerance > 0 ? (int) $tolerance : 300;
    }

    private function defaultAudience(): string
    {
        $audience = config('built-for-cloud.hmac.audience') ?? config('app.url');

        return is_string($audience) && $audience !== '' ? $audience : 'app';
    }
}
