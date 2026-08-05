<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\TestCase;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Assert;

/**
 * @phpstan-require-extends TestCase
 */
trait ContractAssertions
{
    public function assertBuiltForCloudContract(): void
    {
        $this->assertBuiltForCloudMetaContract();
        $this->assertBuiltForCloudOwnershipAuthContract();
        $this->assertBuiltForCloudOnboardingAuthContract();
        $this->assertBuiltForCloudModelContract();
    }

    public function assertBuiltForCloudMetaContract(): void
    {
        $response = $this->getJson('/bfc/meta');

        $response->assertOk()
            ->assertJsonStructure([
                'product',
                'bfc_version',
                'api_version',
                'capabilities',
                'claimed',
            ]);

        Assert::assertIsString($response->json('product'));
        Assert::assertIsString($response->json('bfc_version'));
        Assert::assertIsInt($response->json('api_version'));
        Assert::assertIsArray($response->json('capabilities'));
        Assert::assertIsBool($response->json('claimed'));
        Assert::assertSame(
            [],
            array_values(array_diff(
                ['tokens', 'ownership', 'onboarding', 'webhooks'],
                $response->json('capabilities'),
            )),
            'Built-for-Cloud capabilities are missing required values.',
        );
    }

    public function assertBuiltForCloudOwnershipAuthContract(): void
    {
        $consumeToken = $this->mintBuiltForCloudConsumeToken();

        foreach (['/bfc/ownership/release', '/bfc/ownership/cancel-transfer'] as $uri) {
            $this->postJson($uri)->assertUnauthorized();
            $this->postJson($uri, [], $this->builtForCloudBearerHeaders($consumeToken))->assertForbidden();
        }

        $this->postJson('/bfc/ownership/claim', ['token' => 'invalid-contract-claim'])
            ->assertUnauthorized();
        $this->postJson(
            '/bfc/ownership/claim',
            ['token' => 'invalid-contract-claim'],
            $this->builtForCloudBearerHeaders($consumeToken),
        )->assertUnauthorized();
    }

    public function assertBuiltForCloudOnboardingAuthContract(): void
    {
        $consumeToken = $this->mintBuiltForCloudConsumeToken();

        $this->postJson('/bfc/onboarding/issue', ['email' => 'contract@example.test'])
            ->assertUnauthorized();
        $this->postJson(
            '/bfc/onboarding/issue',
            ['email' => 'contract@example.test'],
            $this->builtForCloudBearerHeaders($consumeToken),
        )->assertForbidden();

        $this->postJson('/bfc/onboarding/exchange', ['token' => 'invalid-contract-onboarding'])
            ->assertUnauthorized();
        $this->postJson(
            '/bfc/onboarding/exchange',
            ['token' => 'invalid-contract-onboarding'],
            $this->builtForCloudBearerHeaders($consumeToken),
        )->assertUnauthorized();
        $this->postJson('/bfc/onboarding/verify')->assertUnauthorized();
        $this->postJson('/bfc/onboarding/verify', [], $this->builtForCloudBearerHeaders('invalid-contract-durable'))
            ->assertUnauthorized();
    }

    public function assertBuiltForCloudModelContract(): void
    {
        foreach ($this->builtForCloudApiTokenColumns() as $column) {
            Assert::assertTrue(
                Schema::hasColumn('api_tokens', $column),
                sprintf('The api_tokens table is missing the expected %s column.', $column),
            );
        }

        Assert::assertSame(['consume', 'admin', 'onboard'], Scope::values());
    }

    public function mintBuiltForCloudAdminToken(string $name = 'contract-admin'): string
    {
        return $this->mintBuiltForCloudToken($name, [Scope::Admin->value]);
    }

    public function mintBuiltForCloudConsumeToken(string $name = 'contract-consume'): string
    {
        return $this->mintBuiltForCloudToken($name, [Scope::Consume->value]);
    }

    /**
     * @param  list<string>  $abilities
     */
    private function mintBuiltForCloudToken(string $name, array $abilities): string
    {
        $plainTextToken = $name.'-'.bin2hex(random_bytes(16));

        ApiToken::query()->create([
            'name' => $name,
            'token_hash' => hash('sha256', $plainTextToken),
            'abilities' => $abilities,
        ]);

        return $plainTextToken;
    }

    /**
     * @return array{Authorization: string}
     */
    private function builtForCloudBearerHeaders(string $plainTextToken): array
    {
        return ['Authorization' => 'Bearer '.$plainTextToken];
    }

    /**
     * @return list<string>
     */
    private function builtForCloudApiTokenColumns(): array
    {
        return [
            'id',
            'name',
            'token_hash',
            'last_used_at',
            'request_count',
            'expires_at',
            'revoked_at',
            'abilities',
            'created_at',
            'updated_at',
        ];
    }
}
