<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
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
        ->and(Schema::hasColumn('ownership', 'owner_token_id'))->toBeFalse()
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
            // `console-guard` and `console-enter` are present because
            // this suite's app is a console-ENABLED deployment whose
            // delegated guard is this package's own (tests/TestCase.php).
            // Both capabilities are conditional on that;
            // ConsoleGuardRegistrationTest and ConsoleDisabledTest drive
            // their absence, and ConsoleEnterForeignGuardTest drives the
            // case where only `console-enter` goes away.
            // `app-action-audit-emit` is UNCONDITIONAL: it names schema
            // and an emission point every install carries, and the verb
            // is in the name because this release ships no way to READ
            // that stream (Console PRD D17).
            // `console-chrome-assets` rides the same condition as
            // `console-enter`, and is named for what is SERVED — the
            // layout and the re-entry interceptor — never for any page
            // of this app wearing them, which is the app's own decision
            // (Console PRD D11).
            'capabilities' => ['tokens', 'ownership', 'onboarding', 'webhooks', 'credentials', 'console-keys', 'console-key-retire', 'console-vitals', 'app-action-audit-emit', 'console-guard', 'console-enter', 'console-chrome-assets'],
            'claimed' => false,
        ]);

    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
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
