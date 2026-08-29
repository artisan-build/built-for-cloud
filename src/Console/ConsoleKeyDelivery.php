<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;
use Illuminate\Http\Request;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * One countersigning-key delivery, parsed and validated (Console PRD
 * D12): the `kid` the vendor wants this key filed under, and the key
 * material itself, already normalized to the ring's storage form.
 *
 * The constructor is private and every factory below validates before
 * calling it, so an instance of this class is by construction a
 * well-formed `kid` plus 64 lower-case hex characters that passed
 * {@see ConsoleKeyring::normalizePublicKey}. That is the only property
 * this class enforces, and the caveat that governs the whole feature
 * applies to it too: **normalizing does not make the material public.**
 * A 32-byte Ed25519 seed that happens to encode a usable curve point
 * validates identically to a public key. Custody is held by the
 * provisioning protocol (the vendor hands over the public half) and by
 * this package containing no code that signs — see
 * {@see ConsoleKeyring}'s class docblock, which names where.
 *
 * It exists because every surface that accepts a key parses one through
 * here — the ownership claim, the onboarding exchange, and the re-key
 * verb over both its transports — and a second copy of "what a delivery
 * looks like" is a copy that drifts.
 */
final readonly class ConsoleKeyDelivery
{
    /**
     * The request field the claim surfaces and the re-key route read a
     * delivery from. One name on every surface.
     */
    public const string FIELD = 'console_key';

    /**
     * @param  string  $keyId  a `kid` {@see ConsoleKeyring::isValidKeyId} accepted
     * @param  string  $publicKey  storage form: lower-case hex of 32 bytes
     */
    private function __construct(
        public string $keyId,
        public string $publicKey,
    ) {}

    /**
     * Validate a `kid` and key material into a delivery.
     *
     * @throws ConsoleKeyRefused when either half is not what the ring stores
     */
    public static function fromParts(string $keyId, string $publicKey): self
    {
        if (! ConsoleKeyring::isValidKeyId($keyId)) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::InvalidMaterial);
        }

        try {
            $normalized = ConsoleKeyring::normalizePublicKey($publicKey);
        } catch (InvalidArgumentException $invalid) {
            // The ring's own refusal, re-typed for the delivery
            // surfaces. Its message is not reused: it is written for a
            // developer reading a stack trace, and this one is printed
            // verbatim to an operator.
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::InvalidMaterial, $invalid);
        }

        return new self($keyId, $normalized);
    }

    /**
     * Read the OPTIONAL delivery off a request (the additive claim-time
     * slot). Absent, or an explicit null, is "no key delivered" — the
     * whole point of the additive reservation is that a claim carrying
     * no key behaves exactly as it did before this release.
     *
     * Anything else present is a delivery ATTEMPT and is validated: a
     * half-filled object refuses rather than being read as absence,
     * because "the key silently did not arrive" is the one outcome a
     * retrofit must never produce.
     *
     * @throws ConsoleKeyRefused
     */
    public static function optionalFrom(#[SensitiveParameter] Request $request): ?self
    {
        if (! $request->has(self::FIELD) || $request->input(self::FIELD) === null) {
            return null;
        }

        return self::fromPayload($request->input(self::FIELD));
    }

    /**
     * Parse an untrusted `{"key_id": ..., "public_key": ...}` payload.
     * Unknown sibling keys are IGNORED, not refused — the contract's
     * compatibility rule 1 runs both ways, and a consumer sending a
     * field a later release defines must not break on an older one.
     *
     * @throws ConsoleKeyRefused
     */
    public static function fromPayload(mixed $payload): self
    {
        if (! is_array($payload)) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::InvalidMaterial);
        }

        $keyId = $payload['key_id'] ?? null;
        $publicKey = $payload['public_key'] ?? null;

        if (! is_string($keyId) || ! is_string($publicKey)) {
            throw ConsoleKeyRefused::because(ConsoleKeyRefusal::InvalidMaterial);
        }

        return self::fromParts($keyId, $publicKey);
    }
}
