<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

it('requires an owner token to issue claim codes', function (): void {
    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 3600,
    ])->assertUnauthorized();

    $consumeToken = mintApiToken('consume-owner', [Scope::Consume->value]);

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 3600,
    ], bearerHeaders($consumeToken))->assertForbidden();
});

it('issues a claim code without leaking it anywhere but the documented field', function (): void {
    $ownerToken = mintApiToken('owner', [Scope::Admin->value]);

    $this->beginLeakWatch('marker-not-yet-known');

    $issue = $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'scope' => Scope::Consume->value,
        'ttl_seconds' => 3600,
    ], bearerHeaders($ownerToken));

    $issue->assertCreated()
        ->assertJsonPath('email', 'person@example.test')
        ->assertJsonStructure(['claim_code', 'email'])
        ->assertJsonMissingPath('swap_token');

    $claimCode = (string) $issue->json('claim_code');

    // The marker only exists once the response is in hand; the watch
    // recorded every channel regardless, so point it at the real code
    // before evaluating.
    $this->leakWatchMarker = $claimCode;
    $this->assertNoLeaks();

    // The documented egress, exactly once.
    expect(substr_count((string) $issue->getContent(), $claimCode))->toBe(1)
        ->and(OnboardingToken::resolve($claimCode))->not->toBeNull();
});

it('requires ttl_seconds and enforces the package bounds on the code alone', function (): void {
    $ownerToken = mintApiToken('owner', [Scope::Admin->value]);

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
    ], bearerHeaders($ownerToken))->assertJsonValidationErrors('ttl_seconds');

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 59,
    ], bearerHeaders($ownerToken))->assertJsonValidationErrors('ttl_seconds');

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 604801,
    ], bearerHeaders($ownerToken))->assertJsonValidationErrors('ttl_seconds');

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 60,
    ], bearerHeaders($ownerToken))->assertCreated();

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 604800,
    ], bearerHeaders($ownerToken))->assertCreated();
});

it('sets the code expiry to exactly issue time plus ttl_seconds with no hidden defaults', function (): void {
    $this->freezeTime();

    $claimCode = issueOnboardingToken('person@example.test', ttlSeconds: 4321);

    $code = OnboardingToken::query()
        ->where('token_hash', OnboardingToken::hashToken($claimCode))
        ->firstOrFail();

    expect($code->expires_at->timestamp)->toBe(now()->addSeconds(4321)->timestamp);
});

it('issues an unaddressed claim code and keeps working with an email', function (): void {
    $ownerToken = mintApiToken('owner', [Scope::Admin->value]);

    $unaddressed = $this->postJson('/bfc/onboarding/issue', [
        'ttl_seconds' => 3600,
    ], bearerHeaders($ownerToken));

    $unaddressed->assertCreated()
        ->assertJsonPath('email', null)
        ->assertJsonStructure(['claim_code']);

    $exchange = $this->postJson('/bfc/onboarding/exchange', [
        'token' => (string) $unaddressed->json('claim_code'),
    ]);

    $exchange->assertCreated()->assertJsonStructure(['durable_token', 'name']);

    $addressed = $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'ttl_seconds' => 3600,
    ], bearerHeaders($ownerToken));

    $addressed->assertCreated()->assertJsonPath('email', 'person@example.test');
});

it('exchanges a claim code for a durable scoped token and verifies it', function (): void {
    $claimCode = issueOnboardingToken('person@example.test');

    $this->beginLeakWatch('marker-not-yet-known');

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode, 'version' => 1]);

    $exchange->assertCreated()
        ->assertJsonPath('name', 'person@example.test')
        ->assertJsonStructure(['durable_token', 'name']);

    $durableToken = (string) $exchange->json('durable_token');

    $this->leakWatchMarker = $durableToken;
    $this->assertNoLeaks();

    expect(substr_count((string) $exchange->getContent(), $durableToken))->toBe(1);

    $row = ApiToken::query()->where('name', 'person@example.test')->firstOrFail();

    expect($row->abilities)->toBe([Scope::Consume->value]);

    // Redemption alone does not burn (make-before-break): the code is
    // still pending until the durable's first successful use.
    $code = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($claimCode))->firstOrFail();

    expect($code->durable_token_id)->toBe($row->getKey())
        ->and($code->consumed_at)->toBeNull();

    $verify = $this->assertNoSecretLeakage($durableToken, function () use ($durableToken): TestResponse {
        return $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken));
    });

    $verify->assertOk()
        ->assertExactJson([
            'ok' => true,
            'name' => 'person@example.test',
            'scope' => Scope::Consume->value,
        ]);

    // First successful use burnt the code.
    expect($code->refresh()->consumed_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken))->assertOk();
});

it('returns a usable token on re-claim before first use with at most one live token per code', function (): void {
    $claimCode = issueOnboardingToken('person@example.test');

    $firstExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $firstExchange->assertCreated();
    $firstDurable = (string) $firstExchange->json('durable_token');
    $firstTokenId = ApiToken::query()->where('name', 'person@example.test')->firstOrFail()->getKey();

    $secondExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $secondExchange->assertCreated();
    $secondDurable = (string) $secondExchange->json('durable_token');

    $firstToken = ApiToken::query()->whereKey($firstTokenId)->firstOrFail();

    expect($firstToken->expires_at)->not->toBeNull()
        ->and($firstToken->revoked_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($firstDurable))
        ->assertNotFound()
        ->assertJsonPath('error', 'code_not_found');
    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($secondDurable))->assertOk();

    // After first use, further claims return code_already_claimed.
    $reclaim = $this->assertNoSecretLeakage($claimCode, function () use ($claimCode): TestResponse {
        return $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    });

    $reclaim->assertStatus(409)->assertJsonPath('error', 'code_already_claimed');

    $this->assertResponseCarriesNoSecret($reclaim, $claimCode);
    $this->assertResponseCarriesNoSecret($reclaim, $secondDurable);
});

it('refuses re-exchange after a completed burn with a secret-free enum message', function (): void {
    $claimCode = issueOnboardingToken('person@example.test');

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    $exchange->assertCreated();
    $durableToken = (string) $exchange->json('durable_token');

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken))->assertOk();

    $reExchange = $this->assertNoSecretLeakage($claimCode, function () use ($claimCode): TestResponse {
        return $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode]);
    });

    $reExchange->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed')
        ->assertJsonStructure(['error', 'message']);

    $this->assertResponseCarriesNoSecret($reExchange, $claimCode);
    $this->assertResponseCarriesNoSecret($reExchange, $durableToken);
});

it('re-issue to the same email and scope supersedes the pending code and its unused durable', function (): void {
    $firstCode = issueOnboardingToken('person@example.test');
    $firstExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $firstCode]);
    $firstExchange->assertCreated();
    $firstDurable = (string) $firstExchange->json('durable_token');
    $firstTokenId = ApiToken::query()->where('name', 'person@example.test')->firstOrFail()->getKey();

    $secondCode = issueOnboardingToken('person@example.test');

    expect(OnboardingToken::resolve($firstCode))->toBeNull()
        ->and(OnboardingToken::resolve($secondCode))->not->toBeNull();

    $firstToken = ApiToken::query()->whereKey($firstTokenId)->firstOrFail();

    expect($firstToken->expires_at)->not->toBeNull()
        ->and($firstToken->revoked_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($firstDurable))
        ->assertNotFound()
        ->assertJsonPath('error', 'code_not_found');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $secondCode])->assertCreated();
});

it('maps every failure path onto the claim error enum with secret-free messages', function (): void {
    // Malformed — not a code shape at all.
    $malformed = $this->postJson('/bfc/onboarding/exchange', ['token' => 'not-a-real-code']);
    $malformed->assertBadRequest()
        ->assertJsonPath('error', 'invalid_code')
        ->assertJsonStructure(['error', 'message']);
    $this->assertResponseCarriesNoSecret($malformed, 'not-a-real-code');

    // Unknown — a well-formed code no row matches.
    $unknownCode = bin2hex(random_bytes(32));
    $unknown = $this->assertNoSecretLeakage($unknownCode, function () use ($unknownCode): TestResponse {
        return $this->postJson('/bfc/onboarding/exchange', ['token' => $unknownCode]);
    });
    $unknown->assertNotFound()->assertJsonPath('error', 'code_not_found');
    $this->assertResponseCarriesNoSecret($unknown, $unknownCode);

    // Expired — past its issue-time TTL.
    $expiredCode = issueOnboardingToken('expired@example.test', ttlSeconds: 60);
    $this->travel(61)->seconds();
    $expired = $this->assertNoSecretLeakage($expiredCode, function () use ($expiredCode): TestResponse {
        return $this->postJson('/bfc/onboarding/exchange', ['token' => $expiredCode]);
    });
    $expired->assertStatus(410)->assertJsonPath('error', 'code_expired');
    $this->assertResponseCarriesNoSecret($expired, $expiredCode);

    // Unsupported contract version.
    $versioned = $this->postJson('/bfc/onboarding/exchange', [
        'token' => bin2hex(random_bytes(32)),
        'version' => 2,
    ]);
    $versioned->assertBadRequest()->assertJsonPath('error', 'unsupported_version');

    // Verify with no credential, and with one that resolves nothing.
    $this->postJson('/bfc/onboarding/verify')
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_code');

    $bogusBearer = 'tok_'.bin2hex(random_bytes(32));
    $unresolved = $this->assertNoSecretLeakage($bogusBearer, function () use ($bogusBearer): TestResponse {
        return $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($bogusBearer));
    });
    $unresolved->assertNotFound()->assertJsonPath('error', 'code_not_found');
    $this->assertResponseCarriesNoSecret($unresolved, $bogusBearer);
});

function issueOnboardingToken(string $email, string $scope = Scope::Consume->value, int $ttlSeconds = 3600): string
{
    $ownerToken = mintApiToken('owner-'.bin2hex(random_bytes(4)), [Scope::Admin->value]);
    $response = test()->postJson('/bfc/onboarding/issue', [
        'email' => $email,
        'scope' => $scope,
        'ttl_seconds' => $ttlSeconds,
    ], bearerHeaders($ownerToken));

    $response->assertCreated();

    return (string) $response->json('claim_code');
}

/**
 * @param  list<string>  $abilities
 */
function mintApiToken(string $name, array $abilities): string
{
    $plainTextToken = $name.'-secret-'.bin2hex(random_bytes(4));

    ApiToken::query()->create([
        'name' => $name,
        'token_hash' => hash('sha256', $plainTextToken),
        'abilities' => $abilities,
    ]);

    return $plainTextToken;
}

/**
 * @return array{Authorization: string}
 */
function bearerHeaders(string $plainTextToken): array
{
    return ['Authorization' => 'Bearer '.$plainTextToken];
}
