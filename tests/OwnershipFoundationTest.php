<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('creates ownership schemas and resolves pending claims by plaintext token', function (): void {
    $plainTextToken = 'claim-secret';
    $claim = OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken($plainTextToken),
    ]);

    OwnershipClaim::query()->create([
        'token_hash' => OwnershipClaim::hashToken('consumed-secret'),
        'consumed_at' => now(),
    ]);

    expect(Schema::hasTable('ownership_claims'))->toBeTrue()
        ->and(Schema::hasColumns('ownership_claims', ['id', 'token_hash', 'consumed_at']))->toBeTrue()
        ->and(Schema::hasTable('ownership'))->toBeTrue()
        ->and(Schema::hasColumns('ownership', ['id', 'owner_credential_id', 'notify_callback', 'webhook_secret', 'pending_claim_id']))->toBeTrue()
        ->and(OwnershipClaim::query()->pending()->count())->toBe(1)
        ->and(OwnershipClaim::resolve($plainTextToken)?->is($claim))->toBeTrue()
        ->and(OwnershipClaim::resolve('consumed-secret'))->toBeNull();
});

it('targets the single ownership credential link at the unified store', function (): void {
    /** @var list<object{table: string, from: string, to: string, on_delete: string}> $foreignKeys */
    $foreignKeys = DB::select("PRAGMA foreign_key_list('ownership')");

    $targets = collect($foreignKeys)
        ->map(static fn (object $key): string => "{$key->from}:{$key->table}.{$key->to}:{$key->on_delete}")
        ->filter(static fn (string $target): bool => str_starts_with($target, 'owner_'))
        ->values()
        ->all();

    expect($targets)->toBe(['owner_credential_id:credentials.id:SET NULL']);
});

it('targets the single onboarding credential link at the unified store', function (): void {
    /** @var list<object{table: string, from: string, to: string, on_delete: string}> $foreignKeys */
    $foreignKeys = DB::select("PRAGMA foreign_key_list('onboarding_tokens')");

    $targets = collect($foreignKeys)
        ->map(static fn (object $key): string => "{$key->from}:{$key->table}.{$key->to}:{$key->on_delete}")
        ->all();

    expect($targets)->toBe(['durable_credential_id:credentials.id:SET NULL']);
});

it('returns unauthenticated bfc meta for unclaimed and claimed environments', function (): void {
    config(['built-for-cloud.product' => 'Sink']);

    $this->getJson('/bfc/meta')
        ->assertOk()
        ->assertExactJson([
            'product' => 'Sink',
            'bfc_version' => BuiltForCloud::VERSION,
            'api_version' => BuiltForCloud::API_VERSION,
            // `app-action-audit-emit` is UNCONDITIONAL: it names schema
            // and an emission point every install carries, and the verb
            // is in the name because this release ships no way to READ
            // that stream (Console PRD D17).
            // `managed-enrolment` is UNCONDITIONAL: the enrolment verbs
            // exist on every install; feature-detect them per
            // docs/http-contract.md "Authority-driven managed enrolment".
            // The conditional delegated-entry capabilities this list once
            // carried (`console-guard`, `console-enter`,
            // `console-chrome-assets`) were removed with the door in
            // v0.17.0.
            'capabilities' => ['tokens', 'ownership', 'onboarding', 'webhooks', 'credentials', 'console-keys', 'console-key-retire', 'console-vitals', 'app-action-audit-emit', 'managed-enrolment'],
            'claimed' => false,
        ]);

    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'owner',
    ]);

    Ownership::query()->create(['owner_credential_id' => $credential->getKey()]);

    $this->getJson('/bfc/meta')
        ->assertOk()
        ->assertJsonPath('claimed', true);
});

it('rate limits the bfc meta route', function (): void {
    $route = Route::getRoutes()->match(request()->create('/bfc/meta', 'GET'));

    expect($route->gatherMiddleware())->toContain('throttle:bfc-public');
});
