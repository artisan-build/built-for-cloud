<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * PRD 1.10 / SEC-8 — the MCP ability vocabulary and its per-tool
 * enforcement primitive. The destructive tool here stands in for sink's
 * PurgeTool: a consuming app wires `bfc.ability:mcp:admin` in front of
 * each destructive MCP tool route and `bfc.ability:mcp:read` in front of
 * each read tool; the locked negatives prove five credential shapes can
 * never invoke the destructive tool.
 */
beforeEach(function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    Route::post('/mcp/purge', fn (): array => ['purged' => true])
        ->middleware('bfc.ability:'.OperatorAbility::McpAdmin->value);

    Route::post('/mcp/status', fn (): array => ['ok' => true])
        ->middleware('bfc.ability:'.OperatorAbility::McpRead->value);
});

it('keeps mcp read and destructive administration as distinct abilities', function (): void {
    expect(OperatorAbility::McpRead->value)->toBe('mcp:read')
        ->and(OperatorAbility::McpAdmin->value)->toBe('mcp:admin')
        ->and(OperatorAbility::McpRead->value)->not->toBe(OperatorAbility::McpAdmin->value);

    // A credential can hold the narrow read ability without ANY
    // destructive ability — and the per-tool gate honors the split.
    $readOnly = $this->mintCredential(['abilities' => [OperatorAbility::McpRead->value]]);

    $this->postJson('/mcp/status', [], ['Authorization' => $readOnly->bearerHeader()])->assertOk();
    $this->postJson('/mcp/purge', [], ['Authorization' => $readOnly->bearerHeader()])->assertForbidden();
});

it('lets a credential holding mcp:admin invoke the destructive tool (the positive control)', function (): void {
    $admin = $this->mintCredential(['abilities' => [OperatorAbility::McpAdmin->value]]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $admin->bearerHeader()])
        ->assertOk()
        ->assertJson(['purged' => true]);
});

// Locked negative 1: an ingest-scoped token cannot invoke a destructive tool.
it('denies an ingest-scoped credential the destructive tool', function (): void {
    $ingest = $this->mintCredential(['abilities' => [Scope::Consume->value]]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $ingest->bearerHeader()])->assertForbidden();
});

it('denies a legacy ingest api_tokens secret the destructive tool outright', function (): void {
    $plaintext = 'legacy-ingest-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'ingest',
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Consume->value],
    ]);

    // The bfc guard authenticates the unified store only: a legacy secret
    // never resolves, so it is 401 before abilities are even consulted.
    $this->postJson('/mcp/purge', [], ['Authorization' => 'Bearer '.$plaintext])->assertUnauthorized();
});

// Locked negative 2: a FALLBACK_TOKEN cannot invoke a destructive tool.
it('denies the fallback token the destructive tool', function (): void {
    config(['built-for-cloud.fallback_token' => 'fallback-secret-bytes']);

    $this->postJson('/mcp/purge', [], ['Authorization' => 'Bearer fallback-secret-bytes'])->assertUnauthorized();
});

// Locked negative 3: an mcp:read token cannot invoke a destructive tool.
it('denies an mcp:read credential the destructive tool and audits the denial', function (): void {
    $readOnly = $this->mintCredential(['abilities' => [OperatorAbility::McpRead->value]]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $readOnly->bearerHeader()])->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('credential_id', $readOnly->credential->id)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->note)->toContain(OperatorAbility::McpAdmin->value);
});

// Locked negative 4: an expired token cannot invoke a destructive tool.
it('denies an expired credential the destructive tool even when it holds mcp:admin', function (): void {
    $expired = $this->mintCredential([
        'abilities' => [OperatorAbility::McpAdmin->value],
        'expires_at' => now()->subMinute(),
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $expired->bearerHeader()])->assertUnauthorized();
});

// Locked negative 5: a revoked token cannot invoke a destructive tool.
it('denies a revoked credential the destructive tool even when it holds mcp:admin', function (): void {
    $revoked = $this->mintCredential([
        'abilities' => [OperatorAbility::McpAdmin->value],
        'revoked_at' => now(),
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $revoked->bearerHeader()])->assertUnauthorized();
});

it('never lets the operator break-glass ability stand in for an mcp ability', function (): void {
    $breakGlass = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    // Exact match per tool: `credential:admin` is the operator surface's
    // break-glass, not an MCP grant of any kind.
    $this->postJson('/mcp/purge', [], ['Authorization' => $breakGlass->bearerHeader()])->assertForbidden();
    $this->postJson('/mcp/status', [], ['Authorization' => $breakGlass->bearerHeader()])->assertForbidden();
});
