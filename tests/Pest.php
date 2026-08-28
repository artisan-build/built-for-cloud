<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Carbon\CarbonImmutable;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Purpose;

uses(TestCase::class)->in(__DIR__);

/**
 * Shared helpers for the audit-stream tests (loaded here so any single
 * test file runs standalone).
 */
function auditAdminToken(string $name = 'audit-admin'): string
{
    $plaintext = $name.'-secret-'.bin2hex(random_bytes(8));

    ApiToken::query()->create([
        'name' => $name,
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
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
    ], ['Authorization' => 'Bearer '.auditAdminToken('audit-admin-'.bin2hex(random_bytes(4)))]);

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
    return AsymmetricSecretKey::generate(new Version4);
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
 * Flip one character inside a token segment, leaving the wire form
 * intact — the shape a real tampering attempt takes.
 */
function consoleFlipCharacter(string $token, int $offset): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $position = $offset < 0 ? strlen($token) + $offset : $offset;
    $current = $token[$position];
    $token[$position] = $current === 'a' ? 'b' : (str_contains($alphabet, $current) ? 'a' : $current);

    return $token;
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
