<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class ClientIdentityTest extends TestCase
{
    use RefreshDatabase;

    // AC1 — a valid identity is recorded against the token that authenticated.
    public function test_it_records_the_client_identity_of_the_authenticating_token(): void
    {
        $identity = '9f8b1c34-0a2e-4f77-9c1d-6b0f2a5e7d31';

        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $token = $this->adminToken();

        $this->assertSame($identity, $token->client_identity);
        $this->assertNotNull($token->client_identity_last_seen_at);
    }

    // AC2 — stored byte-for-byte: no trim, no normalise, no case-fold, no truncate.
    #[DataProvider('verbatimIdentities')]
    public function test_it_stores_the_client_identity_verbatim(string $identity): void
    {
        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $this->assertSame($identity, $this->adminToken()->client_identity);
    }

    // AC3 — a contract violation is dropped without changing what the request does.
    #[DataProvider('contractViolations')]
    public function test_it_drops_a_contract_violating_client_identity_without_breaking_the_request(string $identity): void
    {
        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $token = $this->adminToken();

        $this->assertNull($token->client_identity);
        $this->assertNull($token->client_identity_last_seen_at);
    }

    // AC3 — the same, for the header sent twice with different values.
    public function test_it_drops_a_client_identity_header_sent_more_than_once(): void
    {
        $headers = $this->adminHeaders();

        $request = Request::create('/api/credentials', 'GET');
        $request->headers->set('Authorization', $headers['Authorization']);
        $request->headers->set(ClientIdentity::HEADER, ['first-identity', 'second-identity']);

        $response = $this->app->make(Kernel::class)->handle($request);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($this->adminToken()->client_identity);
    }

    // AC3 — the rejected value is attacker-controlled and must never reach the log.
    public function test_it_never_logs_a_rejected_client_identity_value(): void
    {
        Log::spy();

        $identity = str_repeat('a', self::MAX_BYTES + 1);

        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(function (string $message, array $context) use ($identity): bool {
                return ! str_contains($message.json_encode($context), $identity)
                    && $context['header'] === ClientIdentity::HEADER
                    && $context['bytes'] === self::MAX_BYTES + 1
                    && $context['reason'] === 'longer than 255 bytes';
            });
    }

    // AC4 — the limit is BYTES, not characters.
    #[DataProvider('boundaryIdentities')]
    public function test_it_accepts_a_client_identity_of_exactly_the_byte_limit(string $identity): void
    {
        $this->assertSame(self::MAX_BYTES, strlen($identity));

        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $this->assertSame($identity, $this->adminToken()->client_identity);
    }

    // AC4 — the limit is BYTES: a value under the CHARACTER limit but over the BYTE limit
    // must be rejected. This is what separates strlen() from mb_strlen().
    public function test_the_client_identity_limit_is_measured_in_bytes_not_characters(): void
    {
        $identity = str_repeat('é', 200);

        $this->assertSame(400, strlen($identity));
        $this->assertSame(200, mb_strlen($identity));

        $this->assertFalse(ClientIdentity::isValid($identity));

        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $this->assertNull($this->adminToken()->client_identity);
    }

    // AC5 — the identity grants nothing: a non-admin token still 403s.
    public function test_a_client_identity_does_not_grant_the_admin_scope(): void
    {
        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer consume-secret',
            ClientIdentity::HEADER => 'consume-client',
        ])->assertForbidden();

        // Attribution is about WHICH token authenticated, not what it may do.
        $token = ApiToken::query()->where('name', 'consume')->firstOrFail();

        $this->assertSame('consume-client', $token->client_identity);
    }

    // AC5 — an unauthenticated request still 401s and records nothing.
    public function test_a_client_identity_alone_authenticates_nothing(): void
    {
        ApiToken::factory()->create(['name' => 'bystander']);

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'unauthenticated-client'])
            ->assertUnauthorized();

        $this->assertFalse(ApiToken::query()->whereNotNull('client_identity')->exists());
    }

    // AC6 — forward-only. The ordering has to be REAL: the legacy row must already exist when
    // this PR's migration runs, or a backfill in up() would sail straight past the assertion.
    public function test_the_migration_does_not_backfill_pre_existing_tokens(): void
    {
        $migration = require __DIR__.'/../database/migrations/2026_08_24_000001_add_client_identity_to_api_tokens_table.php';

        // Wind the schema back to how it stood before this PR.
        $migration->down();

        $this->assertFalse(Schema::hasColumn('api_tokens', 'client_identity'));
        $this->assertFalse(Schema::hasColumn('api_tokens', 'client_identity_last_seen_at'));

        // A token that predates the migration.
        $legacy = ApiToken::factory()->create(['name' => 'legacy']);

        // Now run this PR's migration on its own, with that row already in the table.
        $migration->up();

        $this->assertTrue(Schema::hasColumns('api_tokens', ['client_identity', 'client_identity_last_seen_at']));

        // Read past the model so no cast or cached attribute can mask a backfill.
        $row = DB::table('api_tokens')->where('id', $legacy->getKey())->first();

        $this->assertNotNull($row);
        $this->assertNull($row->client_identity);
        $this->assertNull($row->client_identity_last_seen_at);
    }

    // AC6 — an absent header must not null out what is already stored.
    public function test_a_request_without_the_header_leaves_a_stored_identity_untouched(): void
    {
        $headers = $this->adminHeaders();

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => 'first-client'])->assertOk();

        $seenAt = $this->adminToken()->client_identity_last_seen_at;
        $this->assertNotNull($seenAt);

        $this->travel(1)->minutes();

        $this->getJson('/api/credentials', $headers)->assertOk();

        $token = $this->adminToken();

        $this->assertSame('first-client', $token->client_identity);
        $this->assertTrue($token->client_identity_last_seen_at?->equalTo($seenAt));
    }

    // AC7 — last seen advances on a repeat of the SAME identity.
    public function test_it_refreshes_last_seen_when_the_same_identity_is_presented_again(): void
    {
        $headers = $this->adminHeaders();
        $identity = 'stable-client-id';

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => $identity])->assertOk();

        $seenAt = $this->adminToken()->client_identity_last_seen_at;
        $this->assertNotNull($seenAt);

        $this->travel(1)->minutes();

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => $identity])->assertOk();

        $token = $this->adminToken();

        $this->assertSame($identity, $token->client_identity);
        $this->assertTrue($token->client_identity_last_seen_at?->greaterThan($seenAt));
    }

    public function test_a_changed_identity_overwrites_the_previous_one(): void
    {
        $headers = $this->adminHeaders();

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => 'old-client'])->assertOk();
        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => 'new-client'])->assertOk();

        $this->assertSame('new-client', $this->adminToken()->client_identity);
    }

    // FIX 1 — the onboarding verify endpoint authenticates a real durable token too.
    public function test_it_records_the_client_identity_on_the_onboarding_verify_endpoint(): void
    {
        $plaintext = 'durable-secret';
        ApiToken::factory()->create([
            'name' => 'person@example.test',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->postJson('/bfc/onboarding/verify', [], [
            'Authorization' => 'Bearer '.$plaintext,
            ClientIdentity::HEADER => 'onboarding-client',
        ])->assertOk()->assertJsonPath('ok', true);

        $token = ApiToken::query()->where('name', 'person@example.test')->firstOrFail();

        $this->assertSame('onboarding-client', $token->client_identity);
        $this->assertNotNull($token->client_identity_last_seen_at);
    }

    // FIX 1 — and a violating header does not disturb that endpoint's normal response.
    public function test_a_malformed_client_identity_does_not_disturb_the_onboarding_verify_endpoint(): void
    {
        $plaintext = 'durable-secret';
        ApiToken::factory()->create([
            'name' => 'person@example.test',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->postJson('/bfc/onboarding/verify', [], [
            'Authorization' => 'Bearer '.$plaintext,
            ClientIdentity::HEADER => str_repeat('a', self::MAX_BYTES + 1),
        ])->assertOk()->assertExactJson([
            'ok' => true,
            'name' => 'person@example.test',
            'scope' => Scope::Consume->value,
        ]);

        $this->assertNull(ApiToken::query()->where('name', 'person@example.test')->firstOrFail()->client_identity);
    }

    // FIX 2 — a write that throws must not reach the customer. The column inherits the consuming
    // app's charset, so a contract-VALID identity can genuinely fail to store; dropping the column
    // reproduces that at the driver level without a test double.
    public function test_a_failing_client_identity_write_does_not_break_the_request(): void
    {
        $headers = $this->adminHeaders();

        $expected = $this->getJson('/api/credentials', $headers)->assertOk()->json();

        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->dropColumn('client_identity');
        });

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => 'doomed-client'])
            ->assertOk()
            ->assertExactJson($expected);
    }

    // FIX 2 — nor may a log handler that is itself broken. Both the malformed-header warning and
    // the failure warning that follows it throw here; neither may escape.
    public function test_a_failing_log_handler_does_not_break_the_request(): void
    {
        Log::shouldReceive('warning')->andThrow(new RuntimeException('log handler is down'));

        $this->getJson('/api/credentials', $this->adminHeaders() + [
            ClientIdentity::HEADER => str_repeat('a', self::MAX_BYTES + 1),
        ])->assertOk();

        $this->assertNull($this->adminToken()->client_identity);
    }

    // FIX A — a NUL byte is rejected up front. PostgreSQL truncates a bound value at the first
    // NUL SILENTLY rather than erroring, so accepting one would break store-verbatim and let two
    // distinct identities collide on one row. Verified against PostgreSQL 18.0: "client\0one"
    // stores as "client", and "client\0one"/"client\0two" collide.
    public function test_it_rejects_a_client_identity_containing_a_null_byte(): void
    {
        $identity = "client\0one";

        $this->assertTrue(mb_check_encoding($identity, 'UTF-8'));
        $this->assertSame(10, strlen($identity));
        $this->assertFalse(ClientIdentity::isValid($identity));
        $this->assertSame('contains a null byte', ClientIdentity::rejectionReason($identity));

        $this->getJson('/api/credentials', $this->adminHeaders() + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        $this->assertNull($this->adminToken()->client_identity);
    }

    // FIX C1 — pin the contract's central number. Every other case derives its expectation from
    // the constant, so mutating 255 itself would otherwise go unnoticed.
    public function test_the_byte_limit_is_two_hundred_and_fifty_five(): void
    {
        $this->assertSame(255, ClientIdentity::MAX_BYTES);
        $this->assertTrue(ClientIdentity::isValid(str_repeat('a', 255)));
        $this->assertFalse(ClientIdentity::isValid(str_repeat('a', 256)));
    }

    // FIX B — a driver message routinely echoes the bound value back, and the identity is
    // attacker-controlled. The failure log must carry the exception CLASS and never the bytes.
    public function test_it_never_logs_the_identity_when_the_write_fails(): void
    {
        $identity = 'needle-a1b2c3d4-identity';
        $headers = $this->adminHeaders();

        Schema::table('api_tokens', function (Blueprint $table): void {
            $table->dropColumn('client_identity');
        });

        // Precondition: the exception really does leak the identity, so this test is not vacuous.
        try {
            (new TokenRegistry)->recordClientIdentity($this->adminToken(), $identity);
            $this->fail('expected the write to throw once the column is gone');
        } catch (QueryException $e) {
            $this->assertStringContainsString($identity, $e->getMessage());
        }

        $records = [];
        Log::shouldReceive('warning')->andReturnUsing(
            function (string $message, array $context = []) use (&$records): void {
                $records[] = [$message, $context];
            }
        );

        $this->getJson('/api/credentials', $headers + [ClientIdentity::HEADER => $identity])
            ->assertOk();

        // FIX C3: exactly one report -- an emptied catch block would produce none.
        $this->assertCount(1, $records);
        [$message, $context] = $records[0];

        $this->assertSame(QueryException::class, $context['exception']);
        $this->assertStringNotContainsString($identity, $message.json_encode($context));
    }

    // FIX C2 — the absent-header early return. Without it every headerless request would emit a
    // warning; DB state is identical either way, so only the log can catch this.
    public function test_a_request_without_the_header_logs_nothing(): void
    {
        $records = [];
        Log::shouldReceive('warning')->andReturnUsing(
            function (string $message, array $context = []) use (&$records): void {
                $records[] = [$message, $context];
            }
        );

        $this->getJson('/api/credentials', $this->adminHeaders())->assertOk();

        $this->assertSame([], $records);
    }

    public function test_the_registry_refuses_to_record_an_invalid_identity(): void
    {
        $token = ApiToken::factory()->create(['name' => 'direct']);
        $registry = new TokenRegistry;

        $this->assertFalse($registry->recordClientIdentity($token, str_repeat('a', self::MAX_BYTES + 1)));
        $this->assertNull($token->refresh()->client_identity);
        $this->assertNull($token->client_identity_last_seen_at);

        // A valid identity is written AND reflected on the in-memory model.
        $this->assertTrue($registry->recordClientIdentity($token, 'direct-client'));
        $this->assertSame('direct-client', $token->client_identity);
        $this->assertNotNull($token->client_identity_last_seen_at);
    }

    #[DataProvider('validatorCases')]
    public function test_it_validates_the_client_identity_contract(string $identity, bool $valid): void
    {
        $this->assertSame($valid, ClientIdentity::isValid($identity));
        $this->assertSame($valid, ClientIdentity::rejectionReason($identity) === null);
    }

    public function test_it_reads_at_most_one_client_identity_header_from_a_request(): void
    {
        $request = Request::create('/');

        $this->assertNull(ClientIdentity::fromRequest($request));

        $request->headers->set(ClientIdentity::HEADER, '  spaced  ');
        $this->assertSame('  spaced  ', ClientIdentity::fromRequest($request));

        $request->headers->set(ClientIdentity::HEADER, ['one', 'two']);
        $this->assertNull(ClientIdentity::fromRequest($request));

        $request->headers->set(ClientIdentity::HEADER, str_repeat('a', self::MAX_BYTES + 1));
        $this->assertNull(ClientIdentity::fromRequest($request));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function verbatimIdentities(): array
    {
        return [
            'uuid' => ['9f8b1c34-0a2e-4f77-9c1d-6b0f2a5e7d31'],
            'multi-byte' => ['клиент-ідентичність'],
            'surrounding whitespace' => ['  spaced  '],
            'mixed case' => ['MiXeD-CaSe-Client'],
            'unicode line separator' => ["a\u{2028}b"],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function contractViolations(): array
    {
        return [
            '256 bytes' => [str_repeat('a', 256)],
            '400 bytes of 200 characters' => [str_repeat('é', 200)],
            'null byte' => ["client\0one"],
            'carriage return' => ["a\rb"],
            'line feed' => ["a\nb"],
            'empty' => [''],
            'invalid utf-8' => ["\xC3\x28"],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function boundaryIdentities(): array
    {
        return [
            'single byte characters' => [str_repeat('a', 255)],
            'multi byte characters' => [str_repeat('é', 127).'a'],
        ];
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function validatorCases(): array
    {
        return [
            'zero bytes' => ['', false],
            'one byte' => ['a', true],
            '255 bytes' => [str_repeat('a', 255), true],
            '255 bytes multi-byte' => [str_repeat('é', 127).'a', true],
            '256 bytes' => [str_repeat('a', 256), false],
            '400 bytes of 200 characters' => [str_repeat('é', 200), false],
            'null byte' => ["a\0b", false],
            'trailing null byte' => ["ab\0", false],
            'carriage return' => ["a\rb", false],
            'line feed' => ["a\nb", false],
            'invalid utf-8' => ["\xC3\x28", false],
            'unicode line separator' => ["a\u{2028}b", true],
        ];
    }

    private const MAX_BYTES = ClientIdentity::MAX_BYTES;

    /**
     * @return array{Authorization: string}
     */
    private function adminHeaders(string $plaintext = 'secret-admin'): array
    {
        ApiToken::factory()->create([
            'name' => 'admin',
            'token_hash' => hash('sha256', $plaintext),
            'abilities' => [Scope::Admin->value],
        ]);

        return ['Authorization' => 'Bearer '.$plaintext];
    }

    private function adminToken(): ApiToken
    {
        return ApiToken::query()->where('name', 'admin')->firstOrFail();
    }
}
