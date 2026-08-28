<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * PRD 1.12 / OSS-8 / EXEC-11 — the hitch claim-contract route, verified
 * against byte-level fixtures taken from `hitch/docs/claim-contract.md`
 * (request shape, success shape, the full error enum with its documented
 * statuses, make-before-break, versioning). This suite is the IN-REPO
 * conformance proof standing in for running the hitch v0.1.0 binary's
 * `--claim` against a live server: every wire byte hitch branches on —
 * the field names, the `error` enum values, the `version` handling — is
 * pinned here exactly as the contract document writes them.
 */

/** Fire the claim exactly as hitch does: one POST, JSON body, no retry. */
function hitchClaim(string $rawBody): TestResponse
{
    return test()->call('POST', '/bfc/claim', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_USER_AGENT' => 'hitch/0.1.0',
    ], $rawBody);
}

function issueClaimCode(int $ttlSeconds = 3600): string
{
    return auditIssueCode('claim-route@example.com', $ttlSeconds);
}

it('mounts the claim route unconditionally at the fixed /bfc/ path with no prefix configuration', function (): void {
    // No config key names this route: the only mention of "claim" in
    // package config would be a gate, and there is none. The credential
    // API keeps its prefix; this surface is hardcoded like every /bfc/*.
    $routes = collect(app('router')->getRoutes()->getRoutes())
        ->filter(fn ($route): bool => in_array('POST', $route->methods(), true))
        ->map(fn ($route): string => '/'.$route->uri());

    expect($routes)->toContain('/bfc/claim')
        ->and(config('built-for-cloud'))->not->toHaveKey('claim');
});

it('exchanges the exact contract request for the exact contract success shape', function (): void {
    $code = issueClaimCode();

    // The request fixture, byte-for-byte the contract's shape with a live
    // code: {"claim_code": "…", "version": 1}.
    $response = hitchClaim('{"claim_code": "'.$code.'", "version": 1}');

    $response->assertOk();

    /** @var array<string, mixed> $body */
    $body = $response->json();

    // The success fixture's exact field set — version, token, name,
    // expires_at — nothing missing, nothing extra to drift.
    expect(array_keys($body))->toBe(['version', 'token', 'name', 'expires_at'])
        ->and($body['version'])->toBe(1)
        ->and($body['token'])->toBeString()->not->toBe('')
        ->and($body['name'])->toBe('claim-route@example.com')
        ->and($body['expires_at'])->toBeNull();

    // The token is the durable credential hitch installs: it authenticates.
    expect(app(TokenRegistry::class)->resolveModel((string) $body['token']))->not->toBeNull();
});

it('answers each contract error enum with its documented status', function (): void {
    // The enum table from the contract doc, byte-level:
    // invalid_code 400, code_not_found 404, code_already_claimed 409,
    // code_expired 410, unsupported_version 400, server_error 5xx.

    // invalid_code — a malformed code (the doc's own example code shape
    // is not a code this server ever issued), and a missing code.
    hitchClaim('{"claim_code": "A1B2-C3D4", "version": 1}')
        ->assertStatus(400)->assertJsonPath('error', 'invalid_code')->assertJsonPath('version', 1);
    hitchClaim('{"version": 1}')
        ->assertStatus(400)->assertJsonPath('error', 'invalid_code');

    // code_not_found — well-formed, but no such code.
    hitchClaim('{"claim_code": "'.str_repeat('ab', 32).'", "version": 1}')
        ->assertStatus(404)->assertJsonPath('error', 'code_not_found')->assertJsonPath('version', 1);

    // code_expired — the ttl passed.
    $expired = issueClaimCode(60);
    $this->travel(2)->minutes();
    hitchClaim('{"claim_code": "'.$expired.'", "version": 1}')
        ->assertStatus(410)->assertJsonPath('error', 'code_expired');
    $this->travelBack();

    // unsupported_version — a version this server does not speak.
    $code = issueClaimCode();
    hitchClaim('{"claim_code": "'.$code.'", "version": 2}')
        ->assertStatus(400)->assertJsonPath('error', 'unsupported_version')->assertJsonPath('version', 1);

    // Every error body carries the contract's three fields exactly.
    $shape = hitchClaim('{"claim_code": "'.str_repeat('cd', 32).'", "version": 1}')->json();
    expect(array_keys((array) $shape))->toBe(['version', 'error', 'message']);
});

it('implements make-before-break: a re-claim before first use returns a usable token, after first use code_already_claimed', function (): void {
    $code = issueClaimCode();

    $first = hitchClaim('{"claim_code": "'.$code.'", "version": 1}')->assertOk();
    $firstToken = (string) $first->json('token');

    // The dropped-response case: rerunning the same one-liner works. The
    // conforming behaviour this server implements is mint-fresh-and-
    // invalidate-the-pending (hashed storage cannot return the same
    // token) — at most one live token per code, ever.
    $second = hitchClaim('{"claim_code": "'.$code.'", "version": 1}')->assertOk();
    $secondToken = (string) $second->json('token');

    $registry = app(TokenRegistry::class);

    expect($secondToken)->not->toBe($firstToken)
        ->and($registry->resolveModel($firstToken))->toBeNull();

    // First successful USE of the token burns the code (the server
    // issuing the token is the server authenticating it)…
    expect($registry->resolveModel($secondToken))->not->toBeNull();

    // …so further claims answer code_already_claimed, with the honest
    // "was used", not "was redeemed", meaning.
    hitchClaim('{"claim_code": "'.$code.'", "version": 1}')
        ->assertStatus(409)
        ->assertJsonPath('error', 'code_already_claimed');

    expect(OnboardingToken::query()->whereNull('consumed_at')->count())->toBe(0);
});

it('answers the retryable server_error shape when the exchange fails unexpectedly', function (): void {
    $code = issueClaimCode();

    $workingMinter = app(DurableCredentialMinter::class);

    app()->bind(DurableCredentialMinter::class, function (): never {
        throw new RuntimeException('driver exploded with secret-adjacent detail');
    });

    $response = hitchClaim('{"claim_code": "'.$code.'", "version": 1}');

    $response->assertStatus(500)
        ->assertExactJson([
            'version' => 1,
            'error' => 'server_error',
            'message' => 'The server hit an unexpected error. It is safe to retry.',
        ]);

    // Transient and retryable: nothing burned, and once the fault clears
    // the SAME code exchanges — the contract's "safe for the user to
    // retry" is real, not aspirational.
    app()->instance(DurableCredentialMinter::class, $workingMinter);

    hitchClaim('{"claim_code": "'.$code.'", "version": 1}')->assertOk();
});

it('refuses a signing-key code before any burn and leaves it presentable on the exchange surface', function (): void {
    $result = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'webhook-client'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 3600]),
    );

    assert($result->secret !== null);
    $signingKeyCode = $result->secret->reveal();

    hitchClaim('{"claim_code": "'.$signingKeyCode.'", "version": 1}')
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_code');

    // No state changed: the code is unconsumed and still delivers the
    // pending key on the surface built for it.
    expect(OnboardingToken::query()->whereNull('consumed_at')->count())->toBe(1);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $signingKeyCode])
        ->assertCreated()
        ->assertJsonPath('kind', 'hmac');
});
