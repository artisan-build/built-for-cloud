<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionPurpose;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Carbon\CarbonImmutable;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Purpose;

uses(TestCase::class)->in(__DIR__);

/** @return array{private: OpenSSLAsymmetricKey, public: string} */
function testsRsaKey(int $bits = 2048): array
{
    $private = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => $bits,
    ]);
    expect($private)->toBeInstanceOf(OpenSSLAsymmetricKey::class);
    $details = openssl_pkey_get_details($private);
    expect($details)->toBeArray();

    return ['private' => $private, 'public' => $details['key']];
}

function testsBoundScope(string $appPurpose = 'reel.application.signing'): BoundCredentialScope
{
    return new BoundCredentialScope(
        $appPurpose,
        new Subject(SubjectType::Installation, 'reel-installation-1'),
        'install_1',
        'app_1',
        'https://reel.example',
    );
}

function testsConfigureBoundPurposes(): void
{
    config([
        'built-for-cloud.credentials.app_purposes' => [
            'reel.application.signing' => CredentialPurpose::Signing->value,
            'matte.callback' => CredentialPurpose::Signing->value,
        ],
        'built-for-cloud.ui.credential_purposes' => [
            'reel.application.signing',
            'matte.callback',
        ],
    ]);
}

function testsDerLength(int $length): string
{
    if ($length < 128) {
        return chr($length);
    }

    $encoded = ltrim(pack('N', $length), "\0");

    return chr(0x80 | strlen($encoded)).$encoded;
}

function testsDerInteger(string $bytes): string
{
    $bytes = ltrim($bytes, "\0");
    $bytes = $bytes === '' ? "\0" : $bytes;

    if ((ord($bytes[0]) & 0x80) !== 0) {
        $bytes = "\0".$bytes;
    }

    return "\x02".testsDerLength(strlen($bytes)).$bytes;
}

function testsPkcs1PublicKey(string $modulus, string $exponent): string
{
    $body = testsDerInteger($modulus).testsDerInteger($exponent);
    $der = "\x30".testsDerLength(strlen($body)).$body;

    return "-----BEGIN RSA PUBLIC KEY-----\n"
        .chunk_split(base64_encode($der), 64, "\n")
        ."-----END RSA PUBLIC KEY-----\n";
}

/**
 * Shared helpers for the audit-stream tests (loaded here so any single
 * test file runs standalone).
 *
 * @param  list<string>  $abilities
 */
function auditOperatorCredential(
    string $name = 'audit-operator',
    array $abilities = [OperatorAbility::Admin->value],
): string {
    $plaintext = $name.'-secret-'.bin2hex(random_bytes(8));

    Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'subject_ref' => $name,
        'name' => $name,
        'secret_hash' => hash('sha256', $plaintext),
        'status' => CredentialStatus::Active,
        'abilities' => $abilities,
    ]);

    return $plaintext;
}

/**
 * Issue a claim code through the real endpoint, optionally addressed.
 */
function auditIssueCode(?string $email, int $ttlSeconds = 3600): string
{
    $response = test()->postJson('/bfc/onboarding/issue', [
        'email' => $email,
        'scope' => Scope::Consume->value,
        'ttl_seconds' => $ttlSeconds,
    ], ['Authorization' => 'Bearer '.auditOperatorCredential('audit-operator-'.bin2hex(random_bytes(4)))]);

    $response->assertCreated();

    return (string) $response->json('claim_code');
}

/**
 * Console assertion helpers (PR1). The package NEVER mints an assertion
 * — the vendor holds every private key — so the mint side lives here in
 * the tests, standing in for Scalpels, and every knob a refusal test
 * needs to break is exposed deliberately.
 */
function consoleKeypair(): AsymmetricSecretKey
{
    // Regenerate past an upstream paseto bug, roughly 1 key in 1040:
    // `AsymmetricSecretKey::raw()` runs the SIGNING key's bytes through
    // `Util::dos2unix()`, a text CRLF normalization applied to binary
    // material, so a 64-byte key that happens to contain the adjacent
    // pair 0x0D 0x0A comes back 63 bytes and libsodium refuses to sign
    // with it. Measured 17 short keys in 20,000 generations, matching
    // the predicted 63/65536.
    //
    // DO NOT DELETE THIS LOOP because it looks paranoid: without it the
    // whole console suite fails roughly one run in twelve, inside
    // `consoleMint()`, with an error that names neither this helper nor
    // the code under test. It is signing-side ONLY — the public key's
    // own `raw()` does no such normalization, so verification, which is
    // all this package ever does, is unaffected and needs no guard in
    // `src/`.
    foreach (range(1, 16) as $ignored) {
        $secret = AsymmetricSecretKey::generate(new Version4);

        if (strlen($secret->raw()) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return $secret;
        }
    }

    throw new RuntimeException('Could not generate a signing key paseto is willing to sign with.');
}

/**
 * File a key on the app's ring and (by default) activate it.
 */
function consoleFileKey(string $keyId, AsymmetricSecretKey $secret, bool $activate = true): ConsoleKey
{
    $keyring = new ConsoleKeyring;

    $key = $keyring->add($keyId, $secret->getPublicKey()->toHexString());

    return $activate ? $keyring->activate($keyId) : $key;
}

/**
 * The claim set a healthy mint carries. Pass `consoleAbsent()` as an
 * override value to REMOVE a claim rather than change it.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function consoleClaims(array $overrides = []): array
{
    $now = CarbonImmutable::now();

    $claims = array_merge([
        'iss' => 'https://scalpels.test',
        'sub' => 'operator_42',
        'aud' => 'https://sink.test',
        'iat' => $now->toAtomString(),
        'nbf' => $now->toAtomString(),
        'exp' => $now->addSeconds(90)->toAtomString(),
        'jti' => 'mint_'.bin2hex(random_bytes(8)),
        'display_name' => 'Jane Operator',
        'role' => 'admin',
    ], $overrides);

    return array_filter($claims, static fn (mixed $value): bool => $value !== consoleAbsent());
}

/**
 * The sentinel {@see consoleClaims()} reads as "leave this claim out".
 * Distinct from null, which is a legitimate value for `on_behalf_of`.
 */
function consoleAbsent(): string
{
    return '__absent__';
}

/**
 * Mint a v4.public assertion the way the vendor would.
 *
 * @param  array<string, mixed>  $claims
 */
function consoleMint(AsymmetricSecretKey $secret, array $claims, string $keyId = 'k1'): string
{
    $builder = (new Builder)
        ->setVersion(new Version4)
        ->setPurpose(Purpose::public())
        ->setKey($secret)
        ->setClaims($claims)
        ->setFooterArray(['kid' => $keyId]);

    // The builder helpfully invents an `exp` an hour out when a token
    // has none; the claim-shape tests need the token that genuinely
    // carries no expiry.
    if (! array_key_exists('exp', $claims)) {
        $builder = $builder->setNonExpiring(true);
    }

    return $builder->toString();
}

/**
 * Rewrite a v4.public token's CLAIMS, keeping the original signature and
 * footer — the shape a real tampering attempt takes.
 *
 * The mutation happens on the decoded bytes rather than on base64
 * characters so the result is provably still decodable base64 carrying
 * valid JSON: a flipped base64 character could instead have broken the
 * encoding or the JSON, and the verifier answers `signature_invalid` for
 * every parse failure alike, so such a test could not tell which check
 * it had actually driven.
 */
function consoleTamperClaims(string $token, string $search, string $replacement): string
{
    [$header, $purpose, $payload, $footer] = explode('.', $token);

    $blob = Base64UrlSafe::decode($payload);
    $claims = substr($blob, 0, -SODIUM_CRYPTO_SIGN_BYTES);
    $signature = substr($blob, -SODIUM_CRYPTO_SIGN_BYTES);

    $tampered = str_replace($search, $replacement, $claims);

    expect($tampered)->not->toBe($claims)
        ->and(json_decode($tampered, true))->toBeArray();

    return implode('.', [
        $header,
        $purpose,
        Base64UrlSafe::encodeUnpadded($tampered.$signature),
        $footer,
    ]);
}

/**
 * Flip one bit of the SIGNATURE, leaving the claims byte-for-byte
 * intact, so the only thing the verifier can be objecting to is the
 * signature itself.
 */
function consoleTamperSignature(string $token): string
{
    [$header, $purpose, $payload, $footer] = explode('.', $token);

    $blob = Base64UrlSafe::decode($payload);
    $blob[strlen($blob) - 1] = chr(ord($blob[strlen($blob) - 1]) ^ 0x01);

    return implode('.', [$header, $purpose, Base64UrlSafe::encodeUnpadded($blob), $footer]);
}

/**
 * Verify through the container, exactly as the enter endpoint will.
 */
function consoleVerify(string $token): Assertion
{
    return app(AssertionVerifier::class)->verify($token);
}

/**
 * Verify a token that MUST be refused, handing back the refusal itself
 * so a test can read the audit reason and the (uniform) message.
 */
function consoleRefusal(string $token): AssertionRefused
{
    try {
        consoleVerify($token);
    } catch (AssertionRefused $refusal) {
        return $refusal;
    }

    throw new RuntimeException('The assertion verified when the test required it to be refused.');
}

/**
 * Delegated-actor helpers. The package NEVER mints an assertion — the
 * vendor holds every private key — so the mint side lives here in the
 * tests, standing in for Scalpels, and every knob a refusal test needs
 * to break is exposed deliberately.
 *
 * `consoleAssertionFor()` builds an assertion OBJECT, which is good for
 * exactly one thing: recording a handoff row. Nothing accepts one as a
 * way into a principal.
 */
function consoleAssertionFor(
    string $issuer = 'https://scalpels.test',
    string $subject = 'operator_42',
    string $displayName = 'Jane Operator',
    ConsoleRole $role = ConsoleRole::Admin,
    ?string $onBehalfOf = null,
    ?AssertionPurpose $purpose = null,
): Assertion {
    $now = CarbonImmutable::now();

    return Assertion::fromVerifiedClaims(
        issuer: $issuer,
        subject: $subject,
        displayName: $displayName,
        role: $role,
        onBehalfOf: $onBehalfOf,
        audience: 'https://sink.test',
        issuedAt: $now,
        expiresAt: $now->addSeconds(90),
        keyId: 'k1',
        id: 'mint_'.bin2hex(random_bytes(8)),
        purpose: $purpose,
    );
}

/**
 * The actor a handoff would leave on file. Storage only — it does NOT
 * start a session and does NOT refuse a deactivated actor — and writing
 * a row here grants nothing, because no principal can be created from
 * one.
 */
function consoleActor(
    string $issuer = 'https://scalpels.test',
    string $subject = 'operator_42',
    string $displayName = 'Jane Operator',
    ConsoleRole $role = ConsoleRole::Admin,
    ?string $onBehalfOf = null,
): DelegatedActor {
    return DelegatedActor::recordHandoff(
        consoleAssertionFor($issuer, $subject, $displayName, $role, $onBehalfOf),
    );
}

/**
 * The signing key this test's assertions are minted with, filed and
 * activated on the ring the first time it is asked for.
 *
 * Memoised in the CONTAINER rather than a static, so it dies with the
 * application at the end of each test — a static would outlive
 * RefreshDatabase and hand the next test a key id that is no longer on
 * the ring.
 */
function consoleTestSigningKey(): AsymmetricSecretKey
{
    if (app()->bound('bfc.testing.console-signing-key')) {
        /** @var AsymmetricSecretKey */
        return app('bfc.testing.console-signing-key');
    }

    $secret = consoleKeypair();

    consoleFileKey('k1', $secret);

    app()->instance('bfc.testing.console-signing-key', $secret);

    return $secret;
}

/**
 * A REAL signed assertion — the bytes the vendor would mint and a
 * delegated door would receive.
 *
 * The verifier's two required config keys are set here rather than in
 * every caller, because a token that cannot be verified is not a stand-in
 * for one that can: the door that consumes it verifies inside its own
 * transaction, so these helpers have to produce something that genuinely
 * passes.
 */
function consoleSignedAssertion(
    string $issuer = 'https://scalpels.test',
    string $subject = 'operator_42',
    string $displayName = 'Jane Operator',
    ConsoleRole $role = ConsoleRole::Admin,
    ?string $onBehalfOf = null,
): string {
    config([
        'built-for-cloud.console.issuer' => $issuer,
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);

    return consoleMint(consoleTestSigningKey(), consoleClaims([
        'iss' => $issuer,
        'sub' => $subject,
        'display_name' => $displayName,
        'role' => $role->value,
        'on_behalf_of' => $onBehalfOf ?? consoleAbsent(),
    ]));
}
