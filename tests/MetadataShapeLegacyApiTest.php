<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * The two `metadata`-classified rows on the legacy `api_tokens` store
 * (docs/http-contract.md "Endpoint classification"), driven through the
 * same conformance instrument as the rest.
 *
 * PHPUnit-style because the legacy credential API is flag-gated at
 * provider boot, which needs a per-class `WithConfig` attribute.
 */
#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class MetadataShapeLegacyApiTest extends TestCase
{
    use ContractAssertions;
    use RefreshDatabase;

    public function test_the_legacy_store_metadata_rows_hold_their_classification(): void
    {
        $admin = $this->mintBuiltForCloudAdminToken('metadata-admin');

        ApiToken::query()->create([
            'name' => 'ingest',
            'token_hash' => hash('sha256', 'ingest-'.bin2hex(random_bytes(8))),
            'abilities' => [Scope::Consume->value],
        ]);

        // DELETE /api/credentials/{name} — `revoked_ids` only.
        $byName = $this->deleteJson('/api/credentials/ingest', [], ['Authorization' => 'Bearer '.$admin])
            ->assertOk();

        $this->assertBuiltForCloudMetadataEndpoint($byName, 'DELETE /api/credentials/{name}');

        // DELETE /api/credentials/id/{id} — an empty 204 body, asserted
        // rather than assumed.
        $token = ApiToken::query()->create([
            'name' => 'ingest-two',
            'token_hash' => hash('sha256', 'ingest2-'.bin2hex(random_bytes(8))),
            'abilities' => [Scope::Consume->value],
        ]);

        $byId = $this->deleteJson('/api/credentials/id/'.$token->getKey(), [], ['Authorization' => 'Bearer '.$admin])
            ->assertNoContent();

        $this->assertBuiltForCloudMetadataEndpoint($byId, 'DELETE /api/credentials/id/{id}');
    }
}
