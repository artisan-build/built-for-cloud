<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnifiedStoreDeclaration;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// Locked AC 10: with a declaration targeting the unified store, exchange
// mints a credentials row (burn semantics intact); the default keeps
// api_tokens. Locked AC 11: the claim-contract wire surfaces are unchanged.

function bindUnifiedStore(): void
{
    app()->bind(CredentialDeclaration::class, UnifiedStoreDeclaration::class);
}

it('keeps minting into api_tokens by default — the seam toggle is opt-in', function (): void {
    $code = auditIssueCode('legacy@example.test');

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect(ApiToken::query()->where('name', 'legacy@example.test')->exists())->toBeTrue()
        ->and(Credential::query()->count())->toBe(0);
});

it('mints a credentials row through the seam when the declaration targets the unified store', function (): void {
    bindUnifiedStore();

    $code = auditIssueCode('rebuilt@example.test');

    $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    // The wire contract is unchanged: same fields, same single reveal.
    $durable = (string) $response->json('durable_token');

    expect($response->json('name'))->toBe('rebuilt@example.test');

    $credential = Credential::query()->sole();

    expect($credential->kind)->toBe(CredentialKind::Bearer)
        ->and($credential->subject_type)->toBe(SubjectType::ExternalConsumer)
        ->and($credential->subject_ref)->toBe('rebuilt@example.test')
        ->and($credential->abilities)->toBe([Scope::Consume->value])
        ->and($credential->secret_hash)->toBe(hash('sha256', $durable));

    // No api_tokens durable was minted (the admin gate token is the only row).
    expect(ApiToken::query()->where('name', 'rebuilt@example.test')->exists())->toBeFalse();

    // The code links to the credentials row, and under the default
    // first_use burn it is NOT consumed at exchange.
    $codeRow = OnboardingToken::query()->where('durable_token_id', $credential->id)->sole();

    expect($codeRow->consumed_at)->toBeNull();

    // The exchange audit event names the new credential.
    expect(
        CredentialAuditEvent::query()
            ->where('credential_id', $credential->id)
            ->where('event', LifecycleEventType::Exchanged->value)
            ->exists(),
    )->toBeTrue();
});

it('keeps first-use burn semantics intact on the unified store: verify burns the code in one transaction', function (): void {
    bindUnifiedStore();

    $code = auditIssueCode('burn@example.test');

    $durable = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()
        ->json('durable_token');

    $credential = Credential::query()->sole();

    // First use through the claim contract's own verify surface.
    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$durable])
        ->assertOk()
        ->assertJsonPath('ok', true)
        ->assertJsonPath('name', 'burn@example.test')
        ->assertJsonPath('scope', Scope::Consume->value);

    expect($credential->refresh()->last_used_at)->not->toBeNull()
        ->and(OnboardingToken::query()->where('durable_token_id', $credential->id)->sole()->consumed_at)->not->toBeNull();

    // The first_used audit event rode the burn's transaction, addressed to
    // the code's intended recipient.
    $event = CredentialAuditEvent::query()
        ->where('credential_id', $credential->id)
        ->where('event', LifecycleEventType::FirstUsed->value)
        ->sole();

    expect($event->recipient)->toBe('burn@example.test');
});

it('re-exchanges make-before-break on the unified store: the pending durable dies, the fresh one lives', function (): void {
    bindUnifiedStore();

    $code = auditIssueCode('reclaim@example.test');

    $first = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    // Re-claim before first use (the lost-token path).
    $second = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    expect($second)->not->toBe($first);

    $firstRow = Credential::query()->where('secret_hash', hash('sha256', $first))->sole();
    $secondRow = Credential::query()->where('secret_hash', hash('sha256', $second))->sole();

    expect($firstRow->revoked_at)->not->toBeNull()
        ->and($secondRow->revoked_at)->toBeNull();

    // A revoked unified durable no longer verifies.
    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$first])
        ->assertNotFound()
        ->assertJsonPath('error', 'code_not_found');
});

// Fix 3: the store transition. The code records which store its durable
// was minted into, and make-before-break revokes in the RECORDED store —
// a declaration switching stores between exchanges must not strand a
// still-live durable in the old one (two live secrets).

it('revokes the recorded api_tokens durable on re-exchange after the declaration switches to the unified store', function (): void {
    // First exchange under the DEFAULT declaration: the durable lands in
    // api_tokens, and under first_use burn the code stays unburned.
    $code = auditIssueCode('switch@example.test');

    $first = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    $apiRow = ApiToken::query()->where('name', 'switch@example.test')->sole();
    $codeRow = OnboardingToken::query()->where('durable_token_id', $apiRow->getKey())->sole();

    expect($codeRow->durableStore())->toBe(DurableStore::ApiTokens)
        ->and($codeRow->consumed_at)->toBeNull()
        ->and($apiRow->token_hash)->toBe(hash('sha256', $first));

    // The app rebuilds: the declaration now targets the unified store.
    bindUnifiedStore();

    // Re-exchange the same unburned code (the lost-token path).
    $second = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    // The old durable died in its RECORDED store — nothing stranded…
    expect($apiRow->refresh()->revoked_at)->not->toBeNull()
        ->and(app(TokenRegistry::class)->resolve($first))->toBeNull();

    // …and exactly ONE live credential exists: the fresh unified row.
    $live = Credential::query()->whereNull('revoked_at')->sole();

    expect($live->secret_hash)->toBe(hash('sha256', $second))
        ->and(ApiToken::query()->where('name', 'switch@example.test')->whereNull('revoked_at')->count())->toBe(0);
});

it('treats a null durable_store as api_tokens — the backfill semantics for pre-column linkages', function (): void {
    $code = auditIssueCode('legacy-null@example.test');

    $first = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    $apiRow = ApiToken::query()->where('name', 'legacy-null@example.test')->sole();

    // Simulate a linkage written before the column existed.
    OnboardingToken::query()
        ->where('durable_token_id', $apiRow->getKey())
        ->update(['durable_store' => null]);

    bindUnifiedStore();

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect($apiRow->refresh()->revoked_at)->not->toBeNull()
        ->and(app(TokenRegistry::class)->resolve($first))->toBeNull()
        ->and(Credential::query()->whereNull('revoked_at')->count())->toBe(1);
});

it('sweeps the live same-subject durable on exchange (D1d) while sparing rows governed by other pending codes', function (): void {
    bindUnifiedStore();

    // A live durable for the same subject+scope, not linked to any code.
    $standing = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sweep@example.test',
        'abilities' => [Scope::Consume->value],
    ]);

    // A durable governed by a DIFFERENT pending code survives the sweep.
    $governed = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sweep@example.test',
        'abilities' => [Scope::Consume->value],
    ]);

    OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'other@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => hash('sha256', 'other-code'),
        'durable_token_id' => $governed->id,
        'expires_at' => now()->addHour(),
    ]);

    $code = auditIssueCode('sweep@example.test');

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect($standing->refresh()->revoked_at)->not->toBeNull()
        ->and($governed->refresh()->revoked_at)->toBeNull();
});
