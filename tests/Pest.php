<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;

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
