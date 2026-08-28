<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use InvalidArgumentException;

/**
 * The canonical envelope every hmac signature covers (SEC-V3-07):
 * algorithm, key id, event type, timestamp, nonce, audience — plus the
 * body's sha256 — joined into ONE unambiguous string both sides compute
 * identically. Signing the envelope, not the bare body, is what makes
 * every rejection in the verifier meaningful: a replayed nonce, a stale
 * timestamp, a re-targeted audience or a substituted algorithm each
 * CHANGES the signed string, so none can be swapped under an existing
 * signature.
 *
 * Wire form — the `BFC-Signature` header, fixed order, strict charsets:
 *
 *   v1,alg=hmac-sha256,key=<id>,event=<type>,ts=<unix>,nonce=<hex>,aud=<audience>,sig=<hex64>
 *
 * Every field's charset excludes commas, whitespace and newlines, so the
 * comma-separated header and the newline-joined canonical string are both
 * injection-proof by construction. {@see parse()} is anchored and
 * exact — an unknown parameter, a reordered parameter, or an out-of-range
 * value is a malformed header, never a guess. The algorithm is parsed
 * permissively and then PINNED ({@see HmacVerifier}): `alg` names what
 * the signature claims, and anything but `hmac-sha256` is rejected as
 * algorithm substitution — there is no negotiation.
 */
final readonly class HmacEnvelope
{
    public const string HEADER = 'BFC-Signature';

    public const string ALGORITHM = 'hmac-sha256';

    private const string KEY_PATTERN = '[0-9a-fA-F-]{1,64}';

    private const string EVENT_PATTERN = '[A-Za-z0-9._-]{1,128}';

    private const string NONCE_PATTERN = '[0-9a-f]{16,64}';

    private const string AUDIENCE_PATTERN = '[^,\s]{1,255}';

    public function __construct(
        public string $keyId,
        public string $eventType,
        public int $timestamp,
        public string $nonce,
        public string $audience,
    ) {
        // Composing-side validation is a programmer-error throw: a signer
        // fed an event type or audience the wire form cannot carry must
        // fail at the caller, never emit an unparseable header.
        foreach ([
            'key id' => [$keyId, self::KEY_PATTERN],
            'event type' => [$eventType, self::EVENT_PATTERN],
            'nonce' => [$nonce, self::NONCE_PATTERN],
            'audience' => [$audience, self::AUDIENCE_PATTERN],
        ] as $field => [$value, $pattern]) {
            if (preg_match('/^'.$pattern.'$/', $value) !== 1) {
                throw new InvalidArgumentException(sprintf('The envelope %s does not fit the signed wire form.', $field));
            }
        }

        if ($timestamp < 0) {
            throw new InvalidArgumentException('The envelope timestamp cannot be negative.');
        }
    }

    /**
     * Parse a presented header into the envelope and the signature it
     * claims. The CLAIMED algorithm is returned for the verifier to pin —
     * parsing does not trust it.
     *
     * @return array{self, string, string} [envelope, claimed algorithm, signature]
     */
    public static function parse(string $header): array
    {
        $pattern = '/^v1,alg=([a-z0-9-]{1,32}),key=('.self::KEY_PATTERN.'),event=('.self::EVENT_PATTERN.'),'
            .'ts=(\d{1,12}),nonce=('.self::NONCE_PATTERN.'),aud=('.self::AUDIENCE_PATTERN.'),sig=([0-9a-f]{64})$/';

        if (preg_match($pattern, $header, $matches) !== 1) {
            throw HmacVerificationFailed::malformedHeader();
        }

        return [
            new self(
                keyId: $matches[2],
                eventType: $matches[3],
                timestamp: (int) $matches[4],
                nonce: $matches[5],
                audience: $matches[6],
            ),
            $matches[1],
            $matches[7],
        ];
    }

    /**
     * The signed string: version-tagged, newline-joined, body bound by
     * its sha256. No field can contain a newline, so the join is
     * unambiguous.
     */
    public function canonical(string $body): string
    {
        return implode("\n", [
            'bfc-hmac-v1',
            self::ALGORITHM,
            $this->keyId,
            $this->eventType,
            (string) $this->timestamp,
            $this->nonce,
            $this->audience,
            hash('sha256', $body),
        ]);
    }

    public function headerValue(string $signature): string
    {
        return sprintf(
            'v1,alg=%s,key=%s,event=%s,ts=%d,nonce=%s,aud=%s,sig=%s',
            self::ALGORITHM,
            $this->keyId,
            $this->eventType,
            $this->timestamp,
            $this->nonce,
            $this->audience,
            $signature,
        );
    }
}
