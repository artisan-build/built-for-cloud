<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use ArtisanBuild\BuiltForCloud\Subject;

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
    $readOnly = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);

    $this->postJson('/mcp/status', [], ['Authorization' => $readOnly->bearerHeader()])->assertOk();
    $this->postJson('/mcp/purge', [], ['Authorization' => $readOnly->bearerHeader()])->assertForbidden();
});

it('lets a credential holding mcp:admin invoke the destructive tool (the positive control)', function (): void {
    $admin = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpAdmin->value],
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $admin->bearerHeader()])
        ->assertOk()
        ->assertJson(['purged' => true]);
});

// Locked negative 1: an ingest-scoped credential cannot invoke a destructive tool.
it('denies an ingest-scoped credential the destructive tool', function (): void {
    $ingest = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => null,
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $ingest->bearerHeader()])->assertForbidden();
});

// Locked negative 2: an mcp:read credential cannot invoke a destructive tool.
it('denies an mcp:read credential the destructive tool and audits the denial', function (): void {
    $readOnly = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $readOnly->bearerHeader()])->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->where('credential_id', $readOnly->credential->id)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->note)->toContain(OperatorAbility::McpAdmin->value);
});

// Locked negative 3: an expired credential cannot invoke a destructive tool.
it('denies an expired credential the destructive tool even when it holds mcp:admin', function (): void {
    $expired = $this->mintCredential([
        'abilities' => [OperatorAbility::McpAdmin->value],
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'expires_at' => now()->subMinute(),
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $expired->bearerHeader()])->assertUnauthorized();
});

// Locked negative 4: a revoked credential cannot invoke a destructive tool.
it('denies a revoked credential the destructive tool even when it holds mcp:admin', function (): void {
    $revoked = $this->mintCredential([
        'abilities' => [OperatorAbility::McpAdmin->value],
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'revoked_at' => now(),
    ]);

    $this->postJson('/mcp/purge', [], ['Authorization' => $revoked->bearerHeader()])->assertUnauthorized();
});

it('never lets the operator break-glass ability stand in for an mcp ability', function (): void {
    $breakGlass = $this->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::Admin->value],
    ]);

    // Exact match per tool: `credential:admin` is the operator surface's
    // break-glass, not an MCP grant of any kind.
    $this->postJson('/mcp/purge', [], ['Authorization' => $breakGlass->bearerHeader()])->assertUnauthorized();
    $this->postJson('/mcp/status', [], ['Authorization' => $breakGlass->bearerHeader()])->assertUnauthorized();
});

it('preserves stacked auth and ability purpose sets without authorizing the outer set', function (): void {
    $executions = 0;
    Route::get('/stacked-purpose', function () use (&$executions): array {
        $executions++;

        return ['ok' => true];
    })->middleware(['auth:bfc', 'bfc.ability:'.OperatorAbility::McpRead->value]);

    $consumption = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);
    $deployment = $this->mintCredential([
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);

    $this->getJson('/stacked-purpose', ['Authorization' => $consumption->bearerHeader()])->assertOk();
    $this->getJson('/stacked-purpose', ['Authorization' => $deployment->bearerHeader()])->assertUnauthorized();

    expect($executions)->toBe(1)
        ->and($consumption->credential->refresh()->last_used_at)->not->toBeNull()
        // The outer guard legitimately accepts deployment purpose; the inner
        // gate rechecks its narrower set and executes no second pipeline.
        ->and($deployment->credential->refresh()->last_used_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $deployment->credential->id)
            ->where('event', LifecycleEventType::FirstUsed->value)
            ->count())->toBe(1)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $deployment->credential->id)
            ->where('event', LifecycleEventType::DeniedAction->value)
            ->count())->toBe(0);
});

it('refuses wrong-purpose unknown and revoked ability credentials before declaration and denial effects', function (): void {
    $declaration = new class implements CredentialDeclaration
    {
        public int $calls = 0;

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            $this->calls++;

            return true;
        }
    };
    app()->instance(CredentialDeclaration::class, $declaration);

    $wrong = $this->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::McpAdmin->value],
    ]);
    $revoked = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpAdmin->value],
        'revoked_at' => now(),
    ]);

    $wrongResponse = $this->postJson('/mcp/purge', [], ['Authorization' => $wrong->bearerHeader()])->assertUnauthorized();
    $unknownResponse = $this->postJson('/mcp/purge', [], ['Authorization' => 'Bearer unknown'])->assertUnauthorized();
    $revokedResponse = $this->postJson('/mcp/purge', [], ['Authorization' => $revoked->bearerHeader()])->assertUnauthorized();

    expect($wrongResponse->getContent())->toBe($unknownResponse->getContent())
        ->and($revokedResponse->getContent())->toBe($unknownResponse->getContent())
        ->and($declaration->calls)->toBe(0)
        ->and($wrong->credential->refresh()->last_used_at)->toBeNull()
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
});
