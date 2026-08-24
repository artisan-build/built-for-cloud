<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\ClientIdentityObservation;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\DataProvider;

#[WithConfig('built-for-cloud.credential_api.enabled', true, false)]
final class ClientIdentityObservationTest extends TestCase
{
    use RefreshDatabase;

    // AC1 — no bearer at all is the purest NoCredential event.
    public function test_it_observes_a_claimed_identity_when_no_bearer_token_is_present(): void
    {
        $this->enableObservations();

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'ghost-client'])
            ->assertUnauthorized();

        $row = $this->observationFor('ghost-client');

        $this->assertSame(1, $row->observation_count);
        $this->assertNotNull($row->first_seen_at);
        $this->assertNotNull($row->last_seen_at);
        $this->assertSame(1, ClientIdentityObservation::query()->count());
    }

    // AC2 — a bearer that resolves to nothing: unknown, expired, revoked. Each still 401s.
    #[DataProvider('credentialsThatDoNotAuthenticate')]
    public function test_it_observes_a_claimed_identity_when_the_bearer_does_not_resolve(string $bearer, bool $seed, bool $revoked): void
    {
        $this->enableObservations();

        if ($seed) {
            ApiToken::factory()->create([
                'name' => 'dead',
                'token_hash' => hash('sha256', $bearer),
                // Admin scope on purpose: a dead credential 401s regardless of what it could do.
                'abilities' => [Scope::Admin->value],
                'expires_at' => now()->subMinute(),
                'revoked_at' => $revoked ? now()->subMinute() : null,
            ]);
        }

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer '.$bearer,
            ClientIdentity::HEADER => 'ghost-client',
        ])->assertUnauthorized();

        $this->assertSame(1, $this->observationFor('ghost-client')->observation_count);
    }

    // AC3 — a repeat increments in place. first_seen_at is the earliest signal and must not move.
    public function test_a_repeat_claim_increments_in_place_without_a_second_row(): void
    {
        $this->enableObservations();

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'repeat-client'])
            ->assertUnauthorized();

        $before = $this->observationFor('repeat-client');
        $firstSeenAt = $before->first_seen_at;
        $lastSeenAt = $before->last_seen_at;

        $this->travel(1)->minutes();

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'repeat-client'])
            ->assertUnauthorized();

        $after = $this->observationFor('repeat-client');

        $this->assertSame(1, ClientIdentityObservation::query()->count());
        $this->assertSame(2, $after->observation_count);
        $this->assertTrue($after->first_seen_at?->equalTo($firstSeenAt));
        $this->assertTrue($after->last_seen_at?->greaterThan($lastSeenAt));
    }

    // AC4 — a 403 caller HAS a working credential. Not a NoCredential event.
    public function test_a_403_is_not_a_no_credential_event(): void
    {
        $this->enableObservations();

        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer consume-secret',
            ClientIdentity::HEADER => 'scoped-client',
        ])->assertForbidden();

        $this->assertSame(0, ClientIdentityObservation::query()->count());

        // ...and PR1's path is untouched: the identity is still recorded on the token itself.
        $this->assertSame('scoped-client', ApiToken::query()->where('name', 'consume')->firstOrFail()->client_identity);
    }

    // AC4 — the fallback token authenticates, so it is not a NoCredential event either.
    public function test_the_fallback_token_is_not_a_no_credential_event(): void
    {
        $this->enableObservations();

        config(['built-for-cloud.fallback_token' => 'fallback-secret']);

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer fallback-secret',
            ClientIdentity::HEADER => 'fallback-client',
        ])->assertForbidden();

        $this->assertSame(0, ClientIdentityObservation::query()->count());
    }

    // AC5 — OFF by default. No config touched here on purpose.
    public function test_observation_is_off_by_default_and_records_nothing(): void
    {
        $this->assertFalse((bool) config('built-for-cloud.client_identity.observe_unauthenticated'));

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'ghost-client'])
            ->assertUnauthorized();

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer unknown-secret',
            ClientIdentity::HEADER => 'ghost-client',
        ])->assertUnauthorized();

        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->getJson('/api/credentials', [
            'Authorization' => 'Bearer consume-secret',
            ClientIdentity::HEADER => 'ghost-client',
        ])->assertForbidden();

        $this->assertSame(0, ClientIdentityObservation::query()->count());
    }

    // AC6 — a contract violation is never observed, and never changes the 401.
    #[DataProvider('contractViolations')]
    public function test_a_contract_violating_identity_is_never_observed(string $identity): void
    {
        $this->enableObservations();

        $this->getJson('/api/credentials', [ClientIdentity::HEADER => $identity])
            ->assertUnauthorized();

        $this->assertSame(0, ClientIdentityObservation::query()->count());
    }

    // AC6 — the same for a header sent more than once, which needs a real duplicate header value.
    public function test_a_duplicated_identity_header_is_never_observed(): void
    {
        $this->enableObservations();

        $request = Request::create('/api/credentials', 'GET');
        $request->headers->set(ClientIdentity::HEADER, ['first-identity', 'second-identity']);

        $response = $this->app->make(Kernel::class)->handle($request);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(0, ClientIdentityObservation::query()->count());
    }

    // AC7 — at the cap a NEW identity is dropped, existing rows still update, nothing is evicted.
    public function test_the_cap_drops_new_identities_without_evicting_anything(): void
    {
        $this->enableObservations(max: 2);

        $this->claim('client-one');
        $this->claim('client-two');

        $this->assertSame(2, ClientIdentityObservation::query()->count());

        $this->claim('client-three');

        $this->assertSame(2, ClientIdentityObservation::query()->count());
        $this->assertFalse(ClientIdentityObservation::query()->where('client_identity', 'client-three')->exists());

        // Nothing evicted: the earliest-seen identity is still there...
        $this->assertTrue(ClientIdentityObservation::query()->where('client_identity', 'client-one')->exists());

        // ...and existing rows still update at the cap.
        $this->claim('client-one');

        $this->assertSame(2, $this->observationFor('client-one')->observation_count);

        $this->getJson('/api/credentials/client-observations', $this->adminHeaders())
            ->assertOk()
            ->assertJsonPath('at_capacity', true)
            ->assertJsonPath('max_observations', 2);
    }

    // AC8 — the endpoint is admin-token guarded like everything else in this group.
    public function test_the_observations_endpoint_is_admin_token_guarded(): void
    {
        $this->enableObservations();

        ApiToken::factory()->create([
            'name' => 'consume',
            'token_hash' => hash('sha256', 'consume-secret'),
            'abilities' => [Scope::Consume->value],
        ]);

        $this->getJson('/api/credentials/client-observations')->assertUnauthorized();

        $this->getJson('/api/credentials/client-observations', ['Authorization' => 'Bearer consume-secret'])
            ->assertForbidden();
    }

    // AC8 — the advisory nature travels in the payload, not just the README.
    public function test_the_endpoint_declares_itself_advisory_and_spoofable(): void
    {
        $this->enableObservations();

        $this->claim('ghost-client');

        $response = $this->getJson('/api/credentials/client-observations', $this->adminHeaders())->assertOk();

        $response->assertJsonPath('advisory', true)
            ->assertJsonPath('spoofable', true)
            ->assertJsonPath('enabled', true)
            ->assertJsonPath('at_capacity', false);

        $this->assertIsString($response->json('note'));
        $this->assertNotSame('', $response->json('note'));
    }

    // AC8 — exactly the documented per-row fields. An accidental id fails here.
    public function test_an_observation_row_exposes_exactly_the_expected_keys(): void
    {
        $this->enableObservations();

        $this->claim('ghost-client');

        $response = $this->getJson('/api/credentials/client-observations', $this->adminHeaders())->assertOk();

        $rows = $response->json('observations');

        $this->assertNotSame([], $rows);

        foreach ($rows as $row) {
            $this->assertSame([
                'client_identity',
                'first_seen_at',
                'last_seen_at',
                'observation_count',
            ], array_keys($row));
        }

        $this->assertStringNotContainsString('"id"', (string) $response->getContent());
    }

    // AC8 — ordering. Insertion order and last_seen_at order are made to DISAGREE: a test that
    // passes because SQLite happened to return insertion order is a test that cannot fail.
    public function test_the_endpoint_orders_by_last_seen_at_descending(): void
    {
        $this->enableObservations();

        // Inserted first, seen LONGEST ago.
        $this->seedObservation('oldest-signal', now()->subHours(2));
        // Inserted second, seen MOST recently.
        $this->seedObservation('newest-signal', now());
        // Inserted third, in the middle.
        $this->seedObservation('middle-signal', now()->subHour());

        $response = $this->getJson('/api/credentials/client-observations', $this->adminHeaders())->assertOk();

        $this->assertSame(
            ['newest-signal', 'middle-signal', 'oldest-signal'],
            array_column($response->json('observations'), 'client_identity')
        );
    }

    // AC8 — "off" must be distinguishable from "on and nothing seen".
    public function test_the_endpoint_reports_the_feature_as_disabled_without_a_404(): void
    {
        $this->getJson('/api/credentials/client-observations', $this->adminHeaders())
            ->assertOk()
            ->assertJsonPath('enabled', false)
            ->assertJsonPath('advisory', true)
            ->assertJsonPath('spoofable', true)
            ->assertJsonPath('observations', []);
    }

    // AC9 — a write that throws must not change the response the caller was going to get.
    public function test_a_failing_observation_write_does_not_change_the_response(): void
    {
        $this->enableObservations();

        $expected = $this->getJson('/api/credentials')->assertUnauthorized();

        Schema::drop('bfc_client_identity_observations');

        $actual = $this->getJson('/api/credentials', [ClientIdentity::HEADER => 'ghost-client'])
            ->assertUnauthorized();

        $this->assertSame($expected->getContent(), $actual->getContent());
    }

    // AC10 — no combination of claimed identity and broken credential ever succeeds.
    #[DataProvider('combinationsThatMustNeverSucceed')]
    public function test_a_claimed_identity_never_produces_a_success(string $identity, ?string $bearer): void
    {
        $this->enableObservations();

        $headers = [ClientIdentity::HEADER => $identity];

        if ($bearer !== null) {
            $headers['Authorization'] = 'Bearer '.$bearer;
        }

        $status = $this->getJson('/api/credentials', $headers)->status();

        $this->assertContains($status, [401, 403]);
    }

    /**
     * @return array<string, array{string, bool, bool}>
     */
    public static function credentialsThatDoNotAuthenticate(): array
    {
        return [
            'unknown bearer' => ['unknown-secret', false, false],
            'expired token' => ['expired-secret', true, false],
            'revoked token' => ['revoked-secret', true, true],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function contractViolations(): array
    {
        return [
            '256 bytes' => [str_repeat('a', 256)],
            'carriage return' => ["a\rb"],
            'line feed' => ["a\nb"],
            'null byte' => ["a\0b"],
            'invalid utf-8' => ["\xC3\x28"],
            'empty' => [''],
        ];
    }

    /**
     * @return array<string, array{string, string|null}>
     */
    public static function combinationsThatMustNeverSucceed(): array
    {
        return [
            'valid identity, no bearer' => ['ghost-client', null],
            'valid identity, unknown bearer' => ['ghost-client', 'unknown-secret'],
            'invalid identity, no bearer' => [str_repeat('a', 256), null],
            'invalid identity, unknown bearer' => ["a\nb", 'unknown-secret'],
        ];
    }

    private function enableObservations(int $max = 100): void
    {
        config([
            'built-for-cloud.client_identity.observe_unauthenticated' => true,
            'built-for-cloud.client_identity.max_observations' => $max,
        ]);
    }

    /** Drive one NoCredential event through the real middleware path. */
    private function claim(string $identity): void
    {
        $this->getJson('/api/credentials', [ClientIdentity::HEADER => $identity])
            ->assertUnauthorized();
    }

    private function seedObservation(string $identity, \DateTimeInterface $lastSeenAt): void
    {
        ClientIdentityObservation::query()->create([
            'client_identity' => $identity,
            'first_seen_at' => $lastSeenAt,
            'last_seen_at' => $lastSeenAt,
            'observation_count' => 1,
        ]);
    }

    private function observationFor(string $identity): ClientIdentityObservation
    {
        return ClientIdentityObservation::query()->where('client_identity', $identity)->firstOrFail();
    }

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
}
