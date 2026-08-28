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
 * 7. a per-key rate ceiling on ACCEPTED verifications
 *    (`built-for-cloud.hmac.verification_rate_ceiling`, default 1000 per
 *    replay window): checked after the signature verified — only holders
 *    of the key can spend its budget — and before any nonce is stored,
 *    so one credential can never grow the nonce store past its ceiling;
 * 8. a replayed nonce. The nonce is consumed ONLY AFTER the signature
 *    verified — consuming earlier would let an attacker burn a victim's
 *    nonce with a garbage signature.
 *
 * The nonce/rate store is BOUNDED on both axes: TTL — every entry lives
 * one replay window, 2×tolerance + 60s of margin, which covers the whole
 * INCLUSIVE timestamp-acceptance window with room (a message first
 * verified at V satisfies V ≥ ts − tolerance; the last instant its
 * timestamp still verifies is ts + tolerance ≤ V + 2×tolerance, strictly
 * inside the entry's life — so a nonce accepted once cannot be accepted
 * again anywhere in its valid window, boundary included); and
 * CARDINALITY — at most `verification_rate_ceiling` nonce entries (plus
 * one counter) per key per window, so no credential can exhaust the
 * shared cache with unique nonces.
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

        // One replay window for the nonce entries AND the rate counter:
        // 2× the tolerance plus a stated margin, so the entry strictly
        // outlives the inclusive timestamp-acceptance window (see the
        // class docblock for the arithmetic).
        $windowSeconds = $tolerance * 2 + 60;

        // The cardinality bound: accepted verifications per key per
        // window. Only signature-valid requests reach this counter, so
        // nobody without the key can spend a credential's budget — and
        // because it is checked BEFORE the nonce is stored, the nonce
        // store holds at most `ceiling` entries per key per window.
        $ceiling = $this->rateCeiling();
        $rateKey = 'bfc:hmac:rate:'.$envelope->keyId;

        Cache::add($rateKey, 0, $windowSeconds);

        if ((int) Cache::increment($rateKey) > $ceiling) {
            throw HmacVerificationFailed::rateLimited($ceiling);
        }

        $nonceKey = 'bfc:hmac:nonce:'.hash('sha256', $envelope->keyId.'|'.$envelope->nonce);

        if (! Cache::add($nonceKey, 1, $windowSeconds)) {
            throw HmacVerificationFailed::replayedNonce();
        }

        Credential::query()->whereKey($credential->id)->update(['last_used_at' => now()]);

        return $credential;
    }

    private function rateCeiling(): int
    {
        $ceiling = config('built-for-cloud.hmac.verification_rate_ceiling', 1000);

        return is_numeric($ceiling) && (int) $ceiling > 0 ? (int) $ceiling : 1000;
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
