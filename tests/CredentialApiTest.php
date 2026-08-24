<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\DataProvider;

#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class CredentialApiTest extends TestCase
{
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
        ApiToken::factory()->create([
            'name' => 'ci',
            'token_hash' => hash('sha256', $plaintext),
        ]);

        $this->deleteJson('/api/credentials/ci', [], $this->credentialAdminHeaders())
            ->assertNoContent();

        $this->assertNull((new TokenRegistry)->resolve($plaintext));
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

    // AC3 + AC5 — the exact key set of a row. An accidental extra field (token_hash, id) fails
    // here, and so does a dropped pre-existing one.
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
            ], array_keys($row));
        }

        $content = (string) $response->getContent();

        $this->assertStringNotContainsString('token_hash', $content);
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
