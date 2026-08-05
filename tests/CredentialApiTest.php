<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
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
            'abilities' => ['admin'],
        ], $this->credentialAdminHeaders());

        $response->assertCreated()
            ->assertJsonPath('name', 'ci-admin')
            ->assertJsonPath('abilities', ['admin']);

        $plaintext = (string) $response->json('plaintext');
        $hash = hash('sha256', $plaintext);

        $token = ApiToken::query()
            ->where('name', 'ci-admin')
            ->where('token_hash', $hash)
            ->firstOrFail();

        $this->assertSame(['admin'], $token->abilities);

        $this->postJson('/api/credentials', [
            'name' => 'admin-gated',
        ], ['Authorization' => 'Bearer '.$plaintext])->assertCreated();
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
            'abilities' => ['admin'],
        ]);

        $response = $this->getJson('/api/credentials', $this->credentialAdminHeaders());

        $response->assertOk()
            ->assertJsonStructure([
                '*' => ['name', 'last_used_at', 'expires_at', 'revoked_at', 'abilities'],
            ]);

        $this->assertSame('ci', $response->json('0.name'));
        $this->assertSame(['admin'], $response->json('0.abilities'));
        $this->assertStringNotContainsString($plaintext, (string) $response->getContent());
        $this->assertStringNotContainsString('token_hash', (string) $response->getContent());
        $this->assertStringNotContainsString($hash, (string) $response->getContent());
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
            'abilities' => ['admin'],
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
            'string' => ['admin'],
            'non-string item' => [[123]],
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
            'abilities' => ['admin'],
        ]);

        return ['Authorization' => 'Bearer '.$plaintext];
    }
}
