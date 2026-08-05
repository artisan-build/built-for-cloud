<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('requires an owner token to issue onboarding tokens', function (): void {
    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
    ])->assertUnauthorized();

    $consumeToken = mintApiToken('consume-owner', [Scope::Consume->value]);

    $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
    ], bearerHeaders($consumeToken))->assertForbidden();
});

it('exchanges an onboarding code for a durable scoped token and verifies it', function (): void {
    $ownerToken = mintApiToken('owner', [Scope::Admin->value]);

    $issue = $this->postJson('/bfc/onboarding/issue', [
        'email' => 'person@example.test',
        'scope' => Scope::Consume->value,
    ], bearerHeaders($ownerToken));

    $issue->assertCreated()
        ->assertJsonPath('email', 'person@example.test')
        ->assertJsonStructure(['swap_token', 'email']);

    $swapToken = (string) $issue->json('swap_token');

    expect(OnboardingToken::resolve($swapToken))->not->toBeNull();

    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken]);

    $exchange->assertCreated()
        ->assertJsonPath('name', 'person@example.test')
        ->assertJsonStructure(['durable_token', 'name']);

    $durableToken = (string) $exchange->json('durable_token');
    $row = ApiToken::query()->where('name', 'person@example.test')->firstOrFail();

    expect($row->abilities)->toBe([Scope::Consume->value]);

    $verify = $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken));

    $verify->assertOk()
        ->assertExactJson([
            'ok' => true,
            'name' => 'person@example.test',
            'scope' => Scope::Consume->value,
        ]);

    $onboardingToken = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($swapToken))->firstOrFail();

    expect($onboardingToken->durable_token_id)->toBe($row->getKey())
        ->and($onboardingToken->consumed_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken))->assertOk();
});

it('re-exchanges before verify by revoking the prior durable token', function (): void {
    $swapToken = issueOnboardingToken('person@example.test');

    $firstExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken]);
    $firstExchange->assertCreated();
    $firstDurable = (string) $firstExchange->json('durable_token');
    $firstTokenId = ApiToken::query()->where('name', 'person@example.test')->firstOrFail()->getKey();

    $secondExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken]);
    $secondExchange->assertCreated();
    $secondDurable = (string) $secondExchange->json('durable_token');

    $firstToken = ApiToken::query()->whereKey($firstTokenId)->firstOrFail();

    expect($firstToken->expires_at)->not->toBeNull()
        ->and($firstToken->revoked_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($firstDurable))->assertUnauthorized();
    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($secondDurable))->assertOk();
});

it('re-issue to the same email and scope supersedes pending and active prior tokens', function (): void {
    $firstSwap = issueOnboardingToken('person@example.test');
    $firstExchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $firstSwap]);
    $firstExchange->assertCreated();
    $firstDurable = (string) $firstExchange->json('durable_token');
    $firstTokenId = ApiToken::query()->where('name', 'person@example.test')->firstOrFail()->getKey();

    $secondSwap = issueOnboardingToken('person@example.test');

    expect(OnboardingToken::resolve($firstSwap))->toBeNull()
        ->and(OnboardingToken::resolve($secondSwap))->not->toBeNull();

    $firstToken = ApiToken::query()->whereKey($firstTokenId)->firstOrFail();

    expect($firstToken->expires_at)->not->toBeNull()
        ->and($firstToken->revoked_at)->not->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($firstDurable))->assertUnauthorized();
    $this->postJson('/bfc/onboarding/exchange', ['token' => $secondSwap])->assertCreated();
});

it('rejects expired onboarding tokens', function (): void {
    $swapToken = 'expired-swap';

    OnboardingToken::query()->create([
        'email' => 'person@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => OnboardingToken::hashToken($swapToken),
        'expires_at' => now()->subMinute(),
    ]);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken])->assertUnauthorized();
});

it('does not reuse a consumed onboarding token', function (): void {
    $swapToken = issueOnboardingToken('person@example.test');
    $exchange = $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken]);
    $exchange->assertCreated();
    $durableToken = (string) $exchange->json('durable_token');

    $this->postJson('/bfc/onboarding/verify', [], bearerHeaders($durableToken))->assertOk();
    $this->postJson('/bfc/onboarding/exchange', ['token' => $swapToken])->assertUnauthorized();
});

function issueOnboardingToken(string $email, string $scope = Scope::Consume->value): string
{
    $ownerToken = mintApiToken('owner', [Scope::Admin->value]);
    $response = test()->postJson('/bfc/onboarding/issue', [
        'email' => $email,
        'scope' => $scope,
    ], bearerHeaders($ownerToken));

    $response->assertCreated();

    return (string) $response->json('swap_token');
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
