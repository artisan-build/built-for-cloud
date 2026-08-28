<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresPresentationCadence;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTokens;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\DataProvider;

#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class CredentialApiTest extends TestCase
{
    use ContractAssertions;
    use DetectsSecretLeaks;
    use RefreshDatabase;

    public function test_it_issues_a_plain_access_token_through_the_credential_api(): void
    {
        $response = $this->postJson('/api/credentials', [
            'name' => 'ci',
        ], $this->credentialAdminHeaders());

        $response->assertCreated()
            ->assertJsonPath('name', 'ci')
            ->assertJsonPath('abilities', []);

        $plaintext = (string) $response->json('plaintext');
        $hash = hash('sha256', $plaintext);

        $this->assertStringStartsWith('tok_', $plaintext);
        $this->assertTrue(ApiToken::query()->where('name', 'ci')->where('token_hash', $hash)->exists());
        $this->assertFalse(ApiToken::query()->where('token_hash', $plaintext)->exists());
        $this->assertSame('ci', (new TokenRegistry)->resolve($plaintext));
    }

    public function test_it_issues_an_admin_token_through_the_credential_api(): void
    {
        $response = $this->postJson('/api/credentials', [
            'name' => 'ci-admin',
            'abilities' => [Scope::Admin->value],
        ], $this->credentialAdminHeaders());

        $response->assertCreated()
            ->assertJsonPath('name', 'ci-admin')
            ->assertJsonPath('abilities', [Scope::Admin->value]);

        $plaintext = (string) $response->json('plaintext');
        $hash = hash('sha256', $plaintext);

        $token = ApiToken::query()
            ->where('name', 'ci-admin')
            ->where('token_hash', $hash)
            ->firstOrFail();

        $this->assertSame([Scope::Admin->value], $token->abilities);

        $this->postJson('/api/credentials', [
            'name' => 'admin-gated',
        ], ['Authorization' => 'Bearer '.$plaintext])->assertCreated();
    }

    public function test_it_issues_a_consume_token_through_the_credential_api(): void
    {
        $response = $this->postJson('/api/credentials', [
            'name' => 'ci-consume',
            'abilities' => [Scope::Consume->value],
        ], $this->credentialAdminHeaders());

        $response->assertCreated()
            ->assertJsonPath('name', 'ci-consume')
            ->assertJsonPath('abilities', [Scope::Consume->value]);

        $plaintext = (string) $response->json('plaintext');
        $hash = hash('sha256', $plaintext);

        $token = ApiToken::query()
            ->where('name', 'ci-consume')
            ->where('token_hash', $hash)
            ->firstOrFail();

        $this->assertSame([Scope::Consume->value], $token->abilities);
    }

    public function test_admin_gate_rejects_a_consume_only_token(): void
    {
        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->postJson('/api/credentials', [
            'name' => 'consume-gated',
        ], ['Authorization' => 'Bearer consume-secret'])->assertForbidden();
    }

    public function test_it_revokes_a_credential_api_token(): void
    {
        $plaintext = 'ci-secret';
        $token = ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => hash('sha256', $plaintext),
        ]);

        // The name verb reports WHAT actually died — the caller is never
        // guessing which rows a name resolved to.
        $this->deleteJson('/api/credentials/ci', [], $this->credentialAdminHeaders())
            ->assertOk()
            ->assertExactJson(['revoked_ids' => [$token->id]]);

        $this->assertNull((new TokenRegistry)->resolve($plaintext));

        // The revocation is audited to the admin token that presented (D8's
        // actor model on the HTTP path).
        $target = ApiToken::query()->where('name', 'ci')->firstOrFail();
        $admin = ApiToken::query()->where('name', 'admin')->firstOrFail();

        $event = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('credential_id', $target->id)
            ->firstOrFail();

        $this->assertSame(AuditReason::OperatorRequest, $event->reason_code);
        $this->assertSame(AuditActorType::AdminToken, $event->actor_type);
        $this->assertSame($admin->id, $event->actor_ref);
    }

    public function test_it_lists_credential_api_tokens_without_exposing_secrets(): void
    {
        $plaintext = 'list-secret';
        $hash = hash('sha256', $plaintext);

        ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => $hash,
            'last_used_at' => now(),
            'expires_at' => now()->addDay(),
            'revoked_at' => null,
            'abilities' => [Scope::Admin->value],
        ]);

        $response = $this->getJson('/api/credentials', $this->credentialAdminHeaders());

        $response->assertOk()
            ->assertJsonStructure([
                '*' => ['name', 'last_used_at', 'expires_at', 'revoked_at', 'abilities'],
            ]);

        $this->assertSame('ci', $response->json('0.name'));
        $this->assertSame([Scope::Admin->value], $response->json('0.abilities'));
        $this->assertStringNotContainsString($plaintext, (string) $response->getContent());
        $this->assertStringNotContainsString('token_hash', (string) $response->getContent());
        $this->assertStringNotContainsString($hash, (string) $response->getContent());
    }

    // AC1 — the recorded identity comes back byte-identical. Recorded through the REAL PR1 path
    // (a request carrying the header), not a factory write, so the recording half and the
    // listing half drifting apart would fail this.
    #[DataProvider('roundTripIdentities')]
    public function test_it_lists_the_client_identity_recorded_against_a_token(string $identity): void
    {
        $headers = $this->credentialAdminHeaders();

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => $identity])->assertOk();

        $response = $this->getJson('/api/credentials', $headers)->assertOk();

        $response->assertJsonPath('0.name', 'admin');

        // Assert the DECODED value, deliberately -- NOT a byte comparison of the raw body.
        // json_encode escapes U+2028 as \u2028 and a quote as \", which decode back to the
        // identical string. Comparing raw bytes here would be wrong, not stricter.
        $this->assertSame($identity, $response->json('0.client_identity'));
        $this->assertNotNull($response->json('0.client_identity_last_seen_at'));
    }

    // AC2 — present AND null, not absent. Pinned separately so omitting the keys cannot pass.
    public function test_a_token_that_never_carried_a_client_identity_lists_both_keys_as_null(): void
    {
        $headers = $this->credentialAdminHeaders();

        ApiToken::factory()->create(['name' => 'never-seen']);

        $response = $this->getJson('/api/credentials', $headers)->assertOk();

        $rows = $response->json();
        $index = array_search('never-seen', array_column($rows, 'name'), true);

        $this->assertNotFalse($index);
        $this->assertArrayHasKey('client_identity', $rows[$index]);
        $this->assertArrayHasKey('client_identity_last_seen_at', $rows[$index]);

        $response->assertJsonPath($index.'.client_identity', null)
            ->assertJsonPath($index.'.client_identity_last_seen_at', null);
    }

    // The exact-key-set invariant, EXTENDED to the PR5 additive set. An accidental extra field
    // (token_hash, secret_hash, any secret-adjacent column) still fails here, and so does a
    // dropped pre-existing one. The pre-PR5 keys keep their exact positions (additive-only
    // proof); the new keys append after them.
    public function test_a_listing_row_exposes_exactly_the_expected_keys(): void
    {
        $plaintext = 'list-secret';

        ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Admin->value],
        ]);

        $response = $this->getJson('/api/credentials', $this->credentialAdminHeaders())->assertOk();

        $rows = $response->json();

        $this->assertNotSame([], $rows);

        foreach ($rows as $row) {
            $this->assertSame([
                'name',
                'last_used_at',
                'expires_at',
                'revoked_at',
                'abilities',
                'client_identity',
                'client_identity_last_seen_at',
                'id',
                'request_count',
                'subject_type',
                'subject_ref',
                'status',
                'presentation_cadence_seconds',
            ], array_keys($row));
        }

        $content = (string) $response->getContent();

        $this->assertStringNotContainsString('token_hash', $content);
        $this->assertStringNotContainsString('secret_hash', $content);
        $this->assertStringNotContainsString(hash('sha256', $plaintext), $content);
        $this->assertStringNotContainsString($plaintext, $content);
    }

    // AC3 — insertion order and created_at order are made to DISAGREE on purpose. SQLite returns
    // rows in insertion order when there is no ORDER BY, so seeding them in the order we expect
    // back would let the orderBy be deleted outright with the suite still green.
    public function test_the_listing_is_still_ordered_by_created_at(): void
    {
        $base = Carbon::parse('2026-08-24 12:00:00');

        $this->travelTo($base);
        $headers = $this->credentialAdminHeaders();

        // Inserted second, created LAST.
        $this->travelTo($base->copy()->addMinutes(2));
        ApiToken::factory()->create(['name' => 'third']);

        // Inserted last, created SECOND.
        $this->travelTo($base->copy()->addMinutes(1));
        ApiToken::factory()->create(['name' => 'second']);

        $this->travelBack();

        $response = $this->getJson('/api/credentials', $headers)->assertOk();

        $this->assertSame(['admin', 'second', 'third'], array_column($response->json(), 'name'));
    }

    // AC3 — the pre-existing fields carry their STORED VALUES, not just their keys. Without this
    // a column dropped from the SELECT list still lists its key, silently as null.
    public function test_the_listing_returns_the_pre_existing_fields_with_their_stored_values(): void
    {
        $lastUsedAt = Carbon::parse('2026-08-01 09:00:00');
        $expiresAt = Carbon::parse('2026-09-01 09:00:00');
        $revokedAt = Carbon::parse('2026-08-15 09:00:00');

        ApiToken::factory()->create([
            'name' => 'valued',
            'token_hash' => hash('sha256', 'valued-secret'),
            'last_used_at' => $lastUsedAt,
            'expires_at' => $expiresAt,
            'revoked_at' => $revokedAt,
            'abilities' => [Scope::Consume->value],
        ]);

        $row = $this->listingRowFor('valued', $this->credentialAdminHeaders());

        $this->assertSame($lastUsedAt->toJSON(), $row['last_used_at']);
        $this->assertSame($expiresAt->toJSON(), $row['expires_at']);
        $this->assertSame($revokedAt->toJSON(), $row['revoked_at']);
        $this->assertSame([Scope::Consume->value], $row['abilities']);
    }

    // AC3 — abilities is deliberately coerced to [] and must never list as null.
    public function test_a_token_with_no_abilities_lists_an_empty_array(): void
    {
        ApiToken::factory()->create(['name' => 'no-abilities', 'abilities' => null]);

        $row = $this->listingRowFor('no-abilities', $this->credentialAdminHeaders());

        $this->assertSame([], $row['abilities']);
    }

    // PR5 — the additive fields carry their stored values: the row id, the usage counter, and
    // the declared subject. Values, not just keys, so a column dropped from the SELECT cannot
    // silently list as null. Runs under the leak harness: the new surface egresses no secret.
    public function test_the_listing_carries_id_request_count_and_the_declared_subject(): void
    {
        $plaintext = 'subject-secret';
        $headers = $this->credentialAdminHeaders();

        $token = ApiToken::factory()->create([
            'name' => 'installed',
            'token_hash' => hash('sha256', $plaintext),
            'request_count' => 7,
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'install-42',
        ]);

        $row = $this->assertNoSecretLeakage(
            $plaintext,
            fn (): array => $this->listingRowFor('installed', $headers),
        );

        $this->assertSame($token->id, $row['id']);
        $this->assertSame(7, $row['request_count']);
        $this->assertSame('installation', $row['subject_type']);
        $this->assertSame('install-42', $row['subject_ref']);
    }

    // PR5 — declare-don't-guess: a row minted before subjects existed lists BOTH subject keys
    // present and null, never a guessed classification.
    public function test_a_legacy_row_lists_null_subject_type_and_subject_ref(): void
    {
        ApiToken::factory()->create(['name' => 'pre-subjects']);

        $row = $this->listingRowFor('pre-subjects', $this->credentialAdminHeaders());

        $this->assertArrayHasKey('subject_type', $row);
        $this->assertArrayHasKey('subject_ref', $row);
        $this->assertNull($row['subject_type']);
        $this->assertNull($row['subject_ref']);
    }

    // Locked AC2 — status computes `revoked` for a revoked row (revocation wins over the expiry
    // it also sets), `expired` for an expired row, `active` otherwise. `unknown` is RESERVED:
    // every api_tokens row structurally carries the usage signal, so this store never emits it
    // (see ReportedStatus — the case exists for stores whose rows cannot carry the signal).
    public function test_status_computes_revoked_expired_and_active(): void
    {
        $headers = $this->credentialAdminHeaders();

        ApiToken::factory()->create([
            'name' => 'dead',
            'revoked_at' => now()->subHour(),
            'expires_at' => now()->subHour(),
        ]);
        ApiToken::factory()->create([
            'name' => 'lapsed',
            'expires_at' => now()->subMinute(),
        ]);
        ApiToken::factory()->create([
            'name' => 'live',
            'expires_at' => now()->addDay(),
        ]);

        $this->assertSame('revoked', $this->listingRowFor('dead', $headers)['status']);
        $this->assertSame('expired', $this->listingRowFor('lapsed', $headers)['status']);
        $this->assertSame('active', $this->listingRowFor('live', $headers)['status']);
        $this->assertSame('active', $this->listingRowFor('admin', $headers)['status']);
    }

    // PR5 — the default declaration declares NO cadence: every row lists null and the top-level
    // header is absent, leaving the consuming control plane's own default in charge.
    public function test_the_default_declaration_declares_no_presentation_cadence(): void
    {
        $response = $this->getJson('/api/credentials', $this->credentialAdminHeaders())->assertOk();

        $response->assertHeaderMissing(ManageTokens::CADENCE_HEADER);

        $this->assertSame([null], array_values(array_unique(
            array_column($response->json(), 'presentation_cadence_seconds'),
        )));
    }

    // PR5 — a declaration that declares a cadence sees it on every row AND once at the listing
    // top level (the response header — the body has always been a bare array, and wrapping it
    // in an envelope would break every existing consumer).
    public function test_a_declared_presentation_cadence_lists_per_row_and_as_the_top_level_header(): void
    {
        $this->app->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements CredentialDeclaration, DeclaresPresentationCadence
        {
            public function resolveSubject(Request $request): ?Subject
            {
                return null;
            }

            public function authorize(Credential $credential, ?string $ability, Request $request): bool
            {
                return true;
            }

            public function presentationCadenceSeconds(): ?int
            {
                return 604800;
            }
        });

        $response = $this->getJson('/api/credentials', $this->credentialAdminHeaders())->assertOk();

        $response->assertHeader(ManageTokens::CADENCE_HEADER, '604800');

        $this->assertSame([604800], array_values(array_unique(
            array_column($response->json(), 'presentation_cadence_seconds'),
        )));
    }

    // Locked AC3 — revoke-by-id revokes exactly that row: the same-named sibling survives and
    // still authenticates, and the revocation is audited with actor + operator_request. Runs
    // under the leak harness.
    public function test_revoke_by_id_revokes_exactly_that_row_and_a_same_named_sibling_survives(): void
    {
        $headers = $this->credentialAdminHeaders();

        $doomed = ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => hash('sha256', 'doomed-secret'),
        ]);
        ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => hash('sha256', 'sibling-secret'),
        ]);

        $this->assertNoSecretLeakage('doomed-secret', function () use ($doomed, $headers): void {
            $this->deleteJson('/api/credentials/id/'.$doomed->id, [], $headers)->assertNoContent();
        });

        $this->assertNull((new TokenRegistry)->resolve('doomed-secret'));
        $this->assertSame('ci', (new TokenRegistry)->resolve('sibling-secret'));

        $admin = ApiToken::query()->where('name', 'admin')->firstOrFail();

        $event = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('credential_id', $doomed->id)
            ->firstOrFail();

        $this->assertSame(AuditReason::OperatorRequest, $event->reason_code);
        $this->assertSame(AuditActorType::AdminToken, $event->actor_type);
        $this->assertSame($admin->id, $event->actor_ref);
    }

    // REWORK Fix 1 — the anomalous row: revoked_at set, no effective expiry (an import, a manual
    // repair). It lists as revoked while legacy resolution — which ignores revoked_at,
    // test-pinned in TokenCoreTest — still authenticates it. Revoke-by-id must kill what it
    // claims to kill: the row stops resolving, the death is audited, and the original
    // revocation stamp is preserved. Never a silent 204 on a still-live row.
    public function test_revoke_by_id_kills_an_anomalous_row_that_reports_revoked_but_still_resolves(): void
    {
        $headers = $this->credentialAdminHeaders();

        $originalRevokedAt = Carbon::parse('2026-08-20 12:00:00');

        $zombie = ApiToken::factory()->create([
            'name' => 'zombie',
            'token_hash' => hash('sha256', 'zombie-secret'),
            'revoked_at' => $originalRevokedAt,
            'expires_at' => null,
        ]);

        // The anomaly, demonstrated: reported dead, still authenticating.
        $this->assertSame('revoked', $this->listingRowFor('zombie', $headers)['status']);
        $this->assertSame('zombie', (new TokenRegistry)->resolve('zombie-secret'));

        $this->deleteJson('/api/credentials/id/'.$zombie->id, [], $headers)->assertNoContent();

        $this->assertNull((new TokenRegistry)->resolve('zombie-secret'));

        $zombie->refresh();
        $this->assertSame($originalRevokedAt->toJSON(), $zombie->revoked_at?->toJSON());
        $this->assertNotNull($zombie->expires_at);

        $this->assertSame(1, CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('credential_id', $zombie->id)
            ->count());
    }

    // REWORK Fix 1 — a row that is already DEAD (expired: the one state that no longer
    // authenticates) is a truthful idempotent no-op: 204, no audit event.
    public function test_revoke_by_id_of_an_expired_row_is_a_no_op_with_no_event(): void
    {
        $headers = $this->credentialAdminHeaders();

        $expired = ApiToken::factory()->create([
            'name' => 'lapsed',
            'expires_at' => now()->subMinute(),
        ]);

        $this->deleteJson('/api/credentials/id/'.$expired->id, [], $headers)->assertNoContent();

        $this->assertSame(0, CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('credential_id', $expired->id)
            ->count());
    }

    public function test_revoke_by_id_returns_404_for_an_unknown_id(): void
    {
        $this->deleteJson('/api/credentials/id/does-not-exist', [], $this->credentialAdminHeaders())
            ->assertNotFound();
    }

    // Idempotent: a second by-id delete of an already-dead row is 204 and emits NO second
    // revoked event — one death, one audit row.
    public function test_revoke_by_id_is_idempotent_and_never_audits_a_second_death(): void
    {
        $headers = $this->credentialAdminHeaders();

        $token = ApiToken::factory()->create(['name' => 'once']);

        $this->deleteJson('/api/credentials/id/'.$token->id, [], $headers)->assertNoContent();
        $this->deleteJson('/api/credentials/id/'.$token->id, [], $headers)->assertNoContent();

        $this->assertSame(1, CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('credential_id', $token->id)
            ->count());
    }

    // Locked AC7 — the consuming-app contract suite covers the additive listing shape.
    public function test_the_contract_assertions_cover_the_additive_listing_shape(): void
    {
        ApiToken::factory()->create([
            'name' => 'contract-row',
            'subject_type' => SubjectType::Operator->value,
            'subject_ref' => 'scalpels',
        ]);

        $this->assertBuiltForCloudCredentialListingContract();
    }

    // AC4 — regression: PR1 touched this middleware. The listing stays admin-token-guarded.
    public function test_the_listing_remains_admin_token_guarded(): void
    {
        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->getJson('/api/credentials')->assertUnauthorized();

        $this->getJson('/api/credentials', ['Authorization' => 'Bearer consume-secret'])
            ->assertForbidden();
    }

    #[DataProvider('rejectedBearerTokens')]
    public function test_it_rejects_non_admin_unknown_expired_missing_and_fallback_bearer_tokens(string $case, ?string $bearer, int $status): void
    {
        config(['built-for-cloud.fallback_token' => 'fallback-secret']);

        ApiToken::factory()->create([
            'name' => 'access',
            'token_hash' => hash('sha256', 'access-secret'),
            'abilities' => null,
        ]);

        ApiToken::factory()->create([
            'name' => 'expired-admin',
            'token_hash' => hash('sha256', 'expired-admin-secret'),
            'abilities' => [Scope::Admin->value],
            'expires_at' => now()->subMinute(),
        ]);

        $request = $this;

        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer '.$bearer);
        }

        $request->postJson('/api/credentials', ['name' => $case])->assertStatus($status);
    }

    public function test_it_validates_credential_api_token_names_before_storing(): void
    {
        $headers = $this->credentialAdminHeaders();

        $this->postJson('/api/credentials', ['name' => 'fallback'], $headers)
            ->assertUnprocessable();

        $this->postJson('/api/credentials', ['name' => '   '], $headers)
            ->assertUnprocessable();
    }

    #[DataProvider('invalidAbilities')]
    public function test_it_validates_credential_api_token_abilities(mixed $abilities): void
    {
        $this->postJson('/api/credentials', [
            'name' => 'ci',
            'abilities' => $abilities,
        ], $this->credentialAdminHeaders())->assertUnprocessable();
    }

    /**
     * Values the contract permits that are awkward for json_encode: quotes and backslashes get
     * escaped, U+2028 becomes \u2028, and whitespace must survive untrimmed.
     *
     * @return array<string, array{string}>
     */
    public static function roundTripIdentities(): array
    {
        return [
            'uuid' => ['9f8b1c34-0a2e-4f77-9c1d-6b0f2a5e7d31'],
            'multi-byte' => ['клиент-ідентичність'],
            'double quote' => ['client"quoted'],
            'backslash' => ['client\\path\\id'],
            'unicode line separator' => ["a\u{2028}b"],
            'surrounding whitespace' => ['  spaced  '],
        ];
    }

    /**
     * @param  array{Authorization: string}  $headers
     * @return array<string, mixed>
     */
    private function listingRowFor(string $name, array $headers): array
    {
        $rows = $this->getJson('/api/credentials', $headers)->assertOk()->json();

        $index = array_search($name, array_column($rows, 'name'), true);

        $this->assertNotFalse($index, "No listing row named {$name}.");

        return $rows[$index];
    }

    /**
     * @return array<string, array{string, string|null, int}>
     */
    public static function rejectedBearerTokens(): array
    {
        return [
            'non-admin' => ['non-admin', 'access-secret', 403],
            'unknown' => ['unknown', 'garbage', 401],
            'expired-admin' => ['expired-admin', 'expired-admin-secret', 401],
            'missing' => ['missing', null, 401],
            'fallback' => ['fallback', 'fallback-secret', 403],
        ];
    }

    /**
     * @return array<string, array{mixed}>
     */
    public static function invalidAbilities(): array
    {
        return [
            'string' => [Scope::Admin->value],
            'non-string item' => [[123]],
            'unknown scope' => [['superuser']],
        ];
    }

    /**
     * @return array{Authorization: string}
     */
    private function credentialAdminHeaders(string $plaintext = 'secret-admin'): array
    {
        ApiToken::factory()->create([
            'name' => 'admin',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Admin->value],
        ]);

        return ['Authorization' => 'Bearer '.$plaintext];
    }
}
