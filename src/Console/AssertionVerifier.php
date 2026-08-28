<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use Carbon\CarbonImmutable;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Purpose;
use RuntimeException;
use Throwable;

/**
 * The ONE place a console assertion becomes an identity (Console PRD
 * D12/D8/D4/D18). Every delegated entry into this deployment passes
 * through {@see verify()}: it returns an {@see Assertion} or it throws.
 * There is deliberately no "parse", no "peek", and no way to read a
 * claim without having verified the whole token — a second, laxer path
 * into these claims would eventually become the one some caller used.
 *
 * The format is PASETO **v4.public** (Ed25519), and both the protocol
 * collection and the purpose are PINNED at the parser: the token's own
 * header never gets to choose how it is checked, so `v4.local` (which a
 * shared symmetric key would verify) and every older version are refused
 * before any cryptography runs. A signed envelope of a different shape
 * cannot be talked into this door.
 *
 * The order of refusals, and why:
 *
 *  1. **version/purpose** — cheapest, and it fixes the algorithm before
 *     anything attacker-controlled is interpreted;
 *  2. **`kid` → keyring** — the footer names a key; an unknown, pending
 *     or retired key stops here (make-before-break lives in the ring,
 *     {@see ConsoleKeyring});
 *  3. **signature** — everything after this line is claims the vendor
 *     actually signed, so no later check reasons about attacker text;
 *  4. **claim shape and charset** — bounded lengths, no control
 *     characters (the verify-side half of D11's escape-by-construction
 *     promise: the chrome must never be the only thing between a hostile
 *     display name and a rendered page);
 *  5. **role** — {@see ConsoleRole} and nothing else, ever;
 *  6. **issuer** — exactly one issuer in v1 (D18), which is what bounds
 *     per-issuer authority;
 *  7. **audience** — THIS deployment's identity: an assertion minted for
 *     another deployment is worthless here, which is the property that
 *     makes theft of one bundle a one-deployment problem;
 *  8. **not yet valid** — an `iat`/`nbf` further ahead than the
 *     configured skew. The skew is spent HERE and only here, where a
 *     deployment clock trailing the issuer's would otherwise refuse a
 *     freshly minted token; it buys nothing on the expiry side;
 *  9. **TTL bound, on two clocks** — the app enforces D12's 60-120s
 *     upper bound ITSELF rather than trusting the issuer to have been
 *     honest about it, and it enforces it against BOTH the token's own
 *     `iat`→`exp` span and this server's wall clock (`exp` may not sit
 *     further than the bound from now). The claimed span alone is not
 *     enough: a mint dated a few seconds ahead — inside the skew, so
 *     rule 8 lets it through — would claim a legal 120-second life and
 *     still be acceptable here for 120 + skew seconds. Two clocks, one
 *     bound, so no skew can stretch the window past it;
 * 10. **expiry** — `exp` is hard: at `exp` the assertion is dead.
 *
 * Every refusal leaves as {@see AssertionRefused} with one uniform,
 * reason-free message; the {@see AssertionRefusalReason} is for the
 * audit record PR4 writes, never for the presenter.
 *
 * Verification is PURE: it reads the keyring and the clock and writes
 * nothing. The single-use burn of `jti` (D12) belongs to the enter
 * endpoint that owns the transaction, not to the crypto choke point.
 */
final class AssertionVerifier
{
    /** The only header this verifier will look at. */
    public const string HEADER = 'v4.public.';

    /**
     * The bound on the display claims (D11). Long enough for a real
     * human name or an agency's name, short enough that the chrome's
     * badge is a badge; anything longer is refused at the door rather
     * than truncated later by whoever renders it.
     */
    public const int MAX_DISPLAY_LENGTH = 120;

    /** The bound on the identity claims — issuer, subject, audience. */
    public const int MAX_IDENTITY_LENGTH = 255;

    /** The bound on the mint id PR4 burns. */
    public const int MAX_ID_LENGTH = 64;

    /**
     * A whole-token size bound, applied before any parsing: a delegated
     * assertion is a few hundred bytes, and an endpoint that will parse
     * a megabyte of base64 has been handed a cheap way to spend CPU.
     */
    public const int MAX_TOKEN_LENGTH = 4096;

    public function __construct(private readonly ConsoleKeyring $keyring) {}

    /**
     * Verify a presented assertion. Returns the identity it carries, or
     * throws {@see AssertionRefused}.
     *
     * @throws AssertionRefused
     */
    public function verify(string $token): Assertion
    {
        $now = CarbonImmutable::now();

        $parser = $this->pinnedParser();
        $keyId = $this->keyIdOf($token, $parser);

        $key = $this->keyring->verificationKey($keyId, $now);

        try {
            // `skipValidation` skips the LIBRARY'S rule engine and
            // nothing else — the signature is verified unconditionally
            // above it. This verifier owns every clock and claim rule
            // precisely so each one can name its own audit reason; the
            // library's built-in NotExpired would otherwise answer for
            // expiry with a reason of its own choosing.
            $parsed = $parser->setKey($key, true)->parse($token, true);
        } catch (Throwable $failure) {
            throw AssertionRefused::because(AssertionRefusalReason::SignatureInvalid, $failure);
        }

        /** @var array<string, mixed> $claims */
        $claims = $parsed->getClaims();

        $issuer = $this->boundedString($claims, 'iss', self::MAX_IDENTITY_LENGTH);
        $subject = $this->boundedString($claims, 'sub', self::MAX_IDENTITY_LENGTH);
        $audience = $this->boundedString($claims, 'aud', self::MAX_IDENTITY_LENGTH);
        $id = $this->boundedString($claims, 'jti', self::MAX_ID_LENGTH);
        $displayName = $this->boundedString($claims, 'display_name', self::MAX_DISPLAY_LENGTH);
        $onBehalfOf = $this->optionalBoundedString($claims, 'on_behalf_of', self::MAX_DISPLAY_LENGTH);
        $issuedAt = $this->timestamp($claims, 'iat');
        $expiresAt = $this->timestamp($claims, 'exp');
        $notBefore = array_key_exists('nbf', $claims) ? $this->timestamp($claims, 'nbf') : null;

        $role = ConsoleRole::tryFrom(is_string($claims['role'] ?? null) ? $claims['role'] : '');

        if (! $role instanceof ConsoleRole) {
            throw AssertionRefused::because(AssertionRefusalReason::InvalidRole);
        }

        if (! hash_equals($this->issuer(), $issuer)) {
            throw AssertionRefused::because(AssertionRefusalReason::IssuerMismatch);
        }

        if (! hash_equals($this->audience(), $audience)) {
            throw AssertionRefused::because(AssertionRefusalReason::AudienceMismatch);
        }

        // The not-yet-valid clock rule comes FIRST of the three time
        // rules: a token minted well into the future is a clock
        // disagreement, and the audit record should say so rather than
        // report the over-long window that same future date implies.
        $skew = $this->clockSkewSeconds();

        if ($issuedAt->getTimestamp() > $now->getTimestamp() + $skew
            || ($notBefore instanceof CarbonImmutable && $notBefore->getTimestamp() > $now->getTimestamp() + $skew)) {
            throw AssertionRefused::because(AssertionRefusalReason::NotYetValid);
        }

        $lifetime = $expiresAt->getTimestamp() - $issuedAt->getTimestamp();

        if ($lifetime <= 0) {
            throw AssertionRefused::because(AssertionRefusalReason::InvalidClaims);
        }

        $maxTtl = $this->maxTtlSeconds();

        // The bound holds on the token's OWN clock AND on this server's.
        // The claimed span alone is not enough: a mint dated a few
        // seconds ahead (inside the skew, so the rule above lets it
        // through) would claim a legal 120-second life and still be
        // acceptable here for 120 + skew seconds. The wall-clock half
        // caps the window this app will actually honour, whatever `iat`
        // claims — which is what makes the one-sided skew above
        // incapable of stretching an assertion past the bound.
        if ($lifetime > $maxTtl || $expiresAt->getTimestamp() > $now->getTimestamp() + $maxTtl) {
            throw AssertionRefused::because(AssertionRefusalReason::TtlTooLong);
        }

        if ($now->getTimestamp() >= $expiresAt->getTimestamp()) {
            throw AssertionRefused::because(AssertionRefusalReason::Expired);
        }

        return Assertion::fromVerifiedClaims(
            issuer: $issuer,
            subject: $subject,
            displayName: $displayName,
            role: $role,
            onBehalfOf: $onBehalfOf,
            audience: $audience,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            keyId: $keyId,
            id: $id,
        );
    }

    /**
     * A parser that speaks v4.public and nothing else. Both pins are
     * explicit: the collection refuses v1/v2/v3, the purpose refuses
     * `v4.local` — the token never selects its own verification path.
     */
    private function pinnedParser(): Parser
    {
        return new Parser(ProtocolCollection::v4(), Purpose::public());
    }

    /**
     * The `kid` from the token's footer. The footer is UNTRUSTED here —
     * it only SELECTS a key, and PASETO binds the footer into the
     * signature, so a swapped `kid` cannot survive the signature check
     * that follows.
     */
    private function keyIdOf(string $token, Parser $parser): string
    {
        if ($token === '' || strlen($token) > self::MAX_TOKEN_LENGTH) {
            throw AssertionRefused::because(AssertionRefusalReason::MalformedToken);
        }

        if (! str_starts_with($token, self::HEADER)) {
            // A well-formed PASETO of another version or purpose is a
            // VERSION refusal; anything else never was a token.
            throw AssertionRefused::because(preg_match('/^v[1-9]\d*\.(local|public)\./', $token) === 1
                ? AssertionRefusalReason::UnsupportedVersion
                : AssertionRefusalReason::MalformedToken);
        }

        try {
            $keyId = $parser->extractKeyIdFromFooterJson(Parser::extractFooter($token));
        } catch (Throwable $failure) {
            throw AssertionRefused::because(AssertionRefusalReason::MalformedToken, $failure);
        }

        if ($keyId === '') {
            // A token naming no key is indistinguishable, to the caller,
            // from one naming a key nobody filed — and it is the same
            // failure: no keyring row answers for it.
            throw AssertionRefused::because(AssertionRefusalReason::UnknownKey);
        }

        return $keyId;
    }

    /**
     * A required string claim: present, a string, non-empty, within its
     * bound, and free of control characters — the class of input that
     * turns a rendered badge into an injection and a log line into two
     * (D11's verify-side half). `\p{C}` covers the C0/C1 controls,
     * newlines and format characters; the two Unicode line separators
     * are named explicitly because they are line breaks that `\p{C}`
     * does not catch.
     *
     * @param  array<string, mixed>  $claims
     */
    private function boundedString(array $claims, string $claim, int $maxLength): string
    {
        $value = $claims[$claim] ?? null;

        if (! is_string($value) || $value === '' || mb_strlen($value) > $maxLength) {
            throw AssertionRefused::because(AssertionRefusalReason::InvalidClaims);
        }

        if (preg_match('/[\p{C}\p{Zl}\p{Zp}]/u', $value) !== 0) {
            // Non-zero covers both a match (1) and a preg failure
            // (false) — invalid UTF-8 makes the check itself fail, and
            // an unvalidatable claim is refused, never waved through.
            throw AssertionRefused::because(AssertionRefusalReason::InvalidClaims);
        }

        return $value;
    }

    /**
     * The same bound for a claim that may legitimately be absent. An
     * explicit null is "no agency"; a present-but-broken value is a
     * refusal, never a silent null (D4's attribution has to be true).
     *
     * @param  array<string, mixed>  $claims
     */
    private function optionalBoundedString(array $claims, string $claim, int $maxLength): ?string
    {
        if (! array_key_exists($claim, $claims) || $claims[$claim] === null) {
            return null;
        }

        return $this->boundedString($claims, $claim, $maxLength);
    }

    /**
     * A required timestamp claim in RFC 3339 SHAPE. The shape is matched
     * before parsing so that relative and free-form date strings — which
     * a lenient parser would happily turn into a time — are refused as
     * the malformed claims they are.
     *
     * Shape, not full validity: a well-formed-but-impossible date such
     * as `2026-02-30T00:00:00+00:00` is normalized by the parser rather
     * than refused. That is left alone deliberately. These claims arrive
     * signed by the one trusted issuer (D18), the normalized value is
     * still subject to every clock and TTL rule above it, and a stricter
     * calendar check would buy nothing an attacker could otherwise
     * spend.
     *
     * @param  array<string, mixed>  $claims
     */
    private function timestamp(array $claims, string $claim): CarbonImmutable
    {
        $value = $claims[$claim] ?? null;

        if (! is_string($value)
            || preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})\z/', $value) !== 1) {
            throw AssertionRefused::because(AssertionRefusalReason::InvalidClaims);
        }

        try {
            return new CarbonImmutable($value);
        } catch (Throwable $failure) {
            throw AssertionRefused::because(AssertionRefusalReason::InvalidClaims, $failure);
        }
    }

    /**
     * The one issuer this fleet trusts (D18). Absent configuration is a
     * misconfiguration, not a refusal: it fails LOUDLY here rather than
     * quietly accepting whatever issuer a token names.
     */
    private function issuer(): string
    {
        $issuer = config('built-for-cloud.console.issuer');

        if (! is_string($issuer) || $issuer === '') {
            throw new RuntimeException('Console assertions require built-for-cloud.console.issuer to be configured.');
        }

        return $issuer;
    }

    /**
     * THIS deployment's identity — and it must be configured
     * EXPLICITLY. Deliberately unlike the `hmac.audience` precedent,
     * which falls back to `app.url` and then to a literal: D12's
     * per-deployment audience is a containment boundary that has to hold
     * on its own, independently of key custody, and `app.url` is not
     * reliably per-deployment. `http://localhost`, a cloned `.env`, or a
     * shared internal load-balancer hostname would quietly file several
     * deployments under one audience — and an audience two deployments
     * share is an audience that stops a stolen assertion at neither.
     *
     * So an unset audience is a misconfiguration and fails closed and
     * loudly here, rather than verifying against a value nobody chose.
     */
    private function audience(): string
    {
        $audience = config('built-for-cloud.console.audience');

        if (! is_string($audience) || $audience === '') {
            throw new RuntimeException('Console assertions require built-for-cloud.console.audience to be configured explicitly; it deliberately does not fall back to app.url.');
        }

        return $audience;
    }

    private function maxTtlSeconds(): int
    {
        $seconds = config('built-for-cloud.console.assertion_max_ttl_seconds', 120);

        return is_numeric($seconds) && (int) $seconds > 0 ? (int) $seconds : 120;
    }

    private function clockSkewSeconds(): int
    {
        $seconds = config('built-for-cloud.console.clock_skew_seconds', 5);

        return is_numeric($seconds) && (int) $seconds >= 0 ? (int) $seconds : 5;
    }
}
