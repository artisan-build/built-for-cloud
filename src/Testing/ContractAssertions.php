<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Scope;
use Illuminate\Foundation\Testing\TestCase;
use Illuminate\Support\Facades\Artisan;
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

        // The claim surfaces speak the claim contract's error enum: clients
        // branch on `error`, the statuses follow the contract's guidance.
        $this->postJson('/bfc/onboarding/exchange', ['token' => 'invalid-contract-onboarding'])
            ->assertBadRequest()
            ->assertJsonPath('error', 'invalid_code');
        $this->postJson(
            '/bfc/onboarding/exchange',
            ['token' => 'invalid-contract-onboarding'],
            $this->builtForCloudBearerHeaders($consumeToken),
        )->assertBadRequest()
            ->assertJsonPath('error', 'invalid_code');
        $this->postJson('/bfc/onboarding/verify')
            ->assertBadRequest()
            ->assertJsonPath('error', 'invalid_code');
        $this->postJson('/bfc/onboarding/verify', [], $this->builtForCloudBearerHeaders('invalid-contract-durable'))
            ->assertNotFound()
            ->assertJsonPath('error', 'code_not_found');
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

    /**
     * The credential-API listing shape (PRD 1.5). NOT part of
     * assertBuiltForCloudContract(): the credential API is disabled by
     * default, so this is called only from a test that enables it
     * (`built-for-cloud.credential_api.enabled` true before boot).
     *
     * Asserts every listing row carries the full additive field set — the
     * pre-PR5 fields AND `id` / `request_count` / `subject_type` /
     * `subject_ref` / `status` / `presentation_cadence_seconds` — and that
     * no hash column ever appears.
     */
    public function assertBuiltForCloudCredentialListingContract(): void
    {
        $admin = $this->mintBuiltForCloudAdminToken('contract-listing-admin');

        $response = $this->getJson('/api/credentials', $this->builtForCloudBearerHeaders($admin));

        $response->assertOk()
            ->assertJsonStructure([
                '*' => [
                    'name',
                    'last_used_at',
                    'expires_at',
                    'revoked_at',
                    'abilities',
                    'client_identity',
                    'client_identity_last_seen_at',
                    'id',
                    'request_count',
                    'status',
                ],
            ]);

        $rows = $response->json();

        Assert::assertIsArray($rows);
        Assert::assertNotSame([], $rows, 'The credential listing returned no rows to assert against.');

        foreach ($rows as $row) {
            Assert::assertIsArray($row);

            // Nullable fields assert as PRESENT keys, not truthy values.
            foreach (['subject_type', 'subject_ref', 'presentation_cadence_seconds'] as $key) {
                Assert::assertArrayHasKey($key, $row, sprintf('A credential listing row is missing the %s key.', $key));
            }

            Assert::assertArrayNotHasKey('token_hash', $row);
            Assert::assertArrayNotHasKey('secret_hash', $row);
        }

        Assert::assertStringNotContainsString('token_hash', (string) $response->getContent());
        Assert::assertStringNotContainsString('secret_hash', (string) $response->getContent());
    }

    /**
     * The transport-parity suite (PRD 1.0 + 1.6): for each two-transport
     * verb — mint (bearer AND basic_auth deliveries), list, revoke —
     * exercise the SAME action through BOTH transports (`--local` CLI and
     * HTTP) and assert identical outcomes: row state, audit events,
     * delivery-shape content. Run this in a consuming app's CI; a verb
     * that behaves differently per transport is a bug by definition (a
     * verb one transport lacks even more so).
     *
     * LIKE FOR LIKE: each comparison puts the IDENTICAL question to both
     * transports — the same subject_ref, the same inputs, the same
     * pre-state (the first leg's row is cleared, or the targets are
     * provisioned identically) — so a declaration whose answer is
     * conditional on the SUBJECT gives the same answer to both legs and
     * never reads as false transport divergence.
     *
     * The suite runs under the app's ACTIVE declaration. If that
     * declaration denies a verb, the parity it asserts is refusal parity —
     * both transports refuse with the SAME error (message equality: both
     * carry the one action's exception message verbatim), and neither
     * leaves a row behind.
     *
     * SCOPE OF THE GUARANTEE: parity is defined over the verb's own
     * inputs — subject, options, abilities, the target row. The
     * declaration's authorizeVerb hook receives each transport's REAL
     * request by design (resolveSubject needs real context), so a
     * declaration that keys authorization on request internals (headers,
     * IPs, session state) introduces app-owned divergence between the
     * transports; that divergence is the app's choice and outside what
     * this suite asserts.
     */
    public function assertBuiltForCloudTransportParityContract(): void
    {
        $minted = $this->assertBuiltForCloudMintTransportParity();

        $this->assertBuiltForCloudListTransportParity();

        if ($minted) {
            $this->assertBuiltForCloudBasicAuthTransportParity();
            $this->assertBuiltForCloudRevokeTransportParity();
        }
    }

    /**
     * LIKE FOR LIKE: both legs mint the SAME subject_ref with identical
     * inputs — a subject-conditional declaration must see the identical
     * question on each transport, or an app-owned per-subject answer would
     * read as false transport divergence. The CLI leg's row is deleted
     * (its audit events kept) before the HTTP leg runs, so the second
     * mint sees the identical pre-state the first one did.
     *
     * @return bool whether the declaration allowed the mint (false = refusal parity was asserted instead)
     */
    public function assertBuiltForCloudMintTransportParity(): bool
    {
        $admin = $this->mintBuiltForCloudAdminToken('parity-admin');

        $ref = 'parity-mint-'.bin2hex(random_bytes(4));

        $cliExit = Artisan::call('bfc:credential:mint', [
            'subject-type' => 'external_consumer',
            'subject-ref' => $ref,
            '--abilities' => 'consume',
            '--local' => true,
        ]);
        $cliOutput = Artisan::output();

        // Snapshot the CLI leg's outcome, then clear its row so the HTTP
        // leg mints against the identical pre-state.
        $cliSecret = null;
        $cliSnapshot = null;
        $cliRowId = null;

        if (preg_match('/shown once: (\S+)/', $cliOutput, $matches) === 1) {
            $cliSecret = $matches[1];

            /** @var Credential $cliRow */
            $cliRow = Credential::query()->where('secret_hash', hash('sha256', $cliSecret))->sole();
            $cliSnapshot = $cliRow->getAttributes();
            $cliRowId = $cliRow->id;

            $cliRow->delete();
        }

        $httpResponse = $this->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => $ref,
            'abilities' => ['consume'],
        ], $this->builtForCloudBearerHeaders($admin));

        if ($httpResponse->status() === 403) {
            // Refusal parity: the identical question got refused over HTTP,
            // so the CLI must have refused it too — with the SAME error
            // (message equality: both carry the one action's exception
            // message verbatim) — and neither leg leaves a row.
            Assert::assertNotSame(0, $cliExit, 'HTTP refused the mint but the CLI performed it: the transports disagree.');

            $httpMessage = (string) $httpResponse->json('message');

            Assert::assertNotSame('', $httpMessage, 'The HTTP refusal carried no message.');
            Assert::assertSame(
                $httpMessage,
                trim($cliOutput),
                'The CLI refused with a different error than HTTP: the transports disagree on the refusal.',
            );
            Assert::assertSame(
                0,
                Credential::query()->where('subject_ref', $ref)->count(),
                'A refused mint left a credential row behind.',
            );

            return false;
        }

        $httpResponse->assertCreated();
        Assert::assertSame(0, $cliExit, 'The CLI mint failed where the HTTP mint succeeded: the transports disagree.');
        Assert::assertNotNull($cliSecret, 'The CLI mint revealed no secret.');
        Assert::assertSame(1, substr_count($cliOutput, (string) $cliSecret), 'The CLI revealed the secret more than once.');

        Assert::assertSame('bearer', $httpResponse->json('delivery.shape'));
        $httpSecret = (string) $httpResponse->json('delivery.secret');
        Assert::assertNotSame('', $httpSecret);

        /** @var Credential $httpRow */
        $httpRow = Credential::query()->where('secret_hash', hash('sha256', $httpSecret))->sole();

        Assert::assertIsArray($cliSnapshot);
        Assert::assertSame($cliSnapshot['secret_hash'], hash('sha256', (string) $cliSecret));

        // Row-state parity on the identical question — subject fields now
        // INCLUDED, equal by construction, so a difference can only be a
        // transport bug. Only id, hash, and timestamps legitimately vary.
        foreach (['kind', 'status', 'abilities', 'name', 'user_id', 'expires_at', 'subject_type', 'subject_ref'] as $attribute) {
            Assert::assertEquals(
                $cliSnapshot[$attribute] ?? null,
                $httpRow->getAttributes()[$attribute] ?? null,
                sprintf('The %s attribute differs between the CLI-minted and HTTP-minted rows.', $attribute),
            );
        }

        // Audit parity: one `issued` event each (the deleted CLI row's
        // events survive it), attributed to each transport's honest actor.
        Assert::assertSame([LifecycleEventType::Issued->value], $this->builtForCloudEventsFor((string) $cliRowId));
        Assert::assertSame([LifecycleEventType::Issued->value], $this->builtForCloudEventsFor($httpRow->id));

        return true;
    }

    /**
     * The basic_auth delivery, compared across transports on the SAME
     * subject_ref with identical inputs (the CLI leg's row cleared before
     * the HTTP leg, its events kept): same shape, the row id as the
     * presentation-only username, and each password hashing to its own
     * row's stored digest.
     */
    public function assertBuiltForCloudBasicAuthTransportParity(): void
    {
        $admin = $this->mintBuiltForCloudAdminToken('parity-basic-admin');

        $ref = 'parity-basic-'.bin2hex(random_bytes(4));

        $cliExit = Artisan::call('bfc:credential:mint', [
            'subject-type' => 'external_consumer',
            'subject-ref' => $ref,
            '--kind' => 'basic',
            '--local' => true,
        ]);
        $cliOutput = Artisan::output();

        $cliSnapshot = null;
        $cliRowId = null;

        if (preg_match('/shown once: (\S+)/', $cliOutput, $matches) === 1) {
            /** @var Credential $cliRow */
            $cliRow = Credential::query()->where('secret_hash', hash('sha256', $matches[1]))->sole();
            $cliSnapshot = $cliRow->getAttributes();
            $cliRowId = $cliRow->id;

            $cliRow->delete();
        }

        $httpResponse = $this->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => $ref,
            'kind' => 'basic',
        ], $this->builtForCloudBearerHeaders($admin));

        if ($httpResponse->status() === 403) {
            Assert::assertNotSame(0, $cliExit, 'HTTP refused the basic mint but the CLI performed it: the transports disagree.');
            Assert::assertSame(
                (string) $httpResponse->json('message'),
                trim($cliOutput),
                'The CLI refused the basic mint with a different error than HTTP.',
            );
            Assert::assertSame(0, Credential::query()->where('subject_ref', $ref)->count(), 'A refused basic mint left a row behind.');

            return;
        }

        $httpResponse->assertCreated();
        Assert::assertSame(0, $cliExit, 'The CLI basic mint failed where the HTTP mint succeeded: the transports disagree.');
        Assert::assertIsArray($cliSnapshot, 'The CLI basic mint revealed no password.');

        /** @var Credential $httpRow */
        $httpRow = Credential::query()->where('subject_ref', $ref)->sole();

        // The pair, on each transport: username = the row id (presentation
        // only), password = the secret, revealed once.
        Assert::assertStringContainsString('auth.json username: '.$cliRowId, $cliOutput);
        Assert::assertSame(1, preg_match('/shown once: (\S+)/', $cliOutput, $matches), 'The CLI basic mint revealed no password.');
        Assert::assertSame($cliSnapshot['secret_hash'], hash('sha256', $matches[1]));

        Assert::assertSame('basic_auth', $httpResponse->json('delivery.shape'));
        Assert::assertSame($httpRow->id, $httpResponse->json('delivery.username'));
        Assert::assertSame($httpRow->secret_hash, hash('sha256', (string) $httpResponse->json('delivery.password')));

        Assert::assertSame($cliSnapshot['kind'], $httpRow->getAttributes()['kind'], 'The basic-minted rows disagree on kind across transports.');
    }

    public function assertBuiltForCloudListTransportParity(): void
    {
        $admin = $this->mintBuiltForCloudAdminToken('parity-list-admin');

        $cliExit = Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]);
        Assert::assertSame(0, $cliExit);

        $cliRows = json_decode(trim(Artisan::output()), true);

        $httpRows = $this->getJson('/bfc/credentials', $this->builtForCloudBearerHeaders($admin))
            ->assertOk()
            ->json();

        // Identical rows, identical serialization, identical order — the
        // one action serializes for both transports, so this is equality,
        // not resemblance.
        Assert::assertSame($httpRows, $cliRows, 'The CLI and HTTP listings disagree.');
    }

    /**
     * The revoke verb, compared across transports on IDENTICAL targets:
     * two rows minted the same way for the SAME subject_ref, one revoked
     * per transport — so a subject-conditional revoke answer is the same
     * question on both legs.
     */
    public function assertBuiltForCloudRevokeTransportParity(): void
    {
        $admin = $this->mintBuiltForCloudAdminToken('parity-revoke-admin');

        $ref = 'parity-revoke-'.bin2hex(random_bytes(4));

        $targets = [];

        foreach (['cli target', 'http target'] as $leg) {
            Assert::assertSame(0, Artisan::call('bfc:credential:mint', [
                'subject-type' => 'external_consumer',
                'subject-ref' => $ref,
                '--abilities' => 'consume',
                '--local' => true,
            ]), sprintf('Provisioning the %s for revoke parity failed.', $leg));

            Assert::assertSame(1, preg_match('/shown once: (\S+)/', Artisan::output(), $matches));

            $targets[] = Credential::query()->where('secret_hash', hash('sha256', $matches[1]))->sole();
        }

        /** @var Credential $cliTarget */
        /** @var Credential $httpTarget */
        [$cliTarget, $httpTarget] = $targets;

        $cliExit = Artisan::call('bfc:credential:revoke', ['id' => $cliTarget->id, '--local' => true]);
        $cliOutput = Artisan::output();

        $httpResponse = $this->deleteJson('/bfc/credentials/'.$httpTarget->id, [], $this->builtForCloudBearerHeaders($admin));

        if ($httpResponse->status() === 403) {
            Assert::assertNotSame(0, $cliExit, 'HTTP refused the revoke but the CLI performed it: the transports disagree.');
            Assert::assertSame(
                (string) $httpResponse->json('message'),
                trim($cliOutput),
                'The CLI refused the revoke with a different error than HTTP.',
            );
            Assert::assertNull($cliTarget->refresh()->revoked_at, 'A refused revoke killed the CLI row anyway.');
            Assert::assertNull($httpTarget->refresh()->revoked_at, 'A refused revoke killed the HTTP row anyway.');

            return;
        }

        $httpResponse->assertNoContent();
        Assert::assertSame(0, $cliExit, 'The CLI revoke failed where the HTTP revoke succeeded: the transports disagree.');

        Assert::assertNotNull($cliTarget->refresh()->revoked_at);
        Assert::assertNotNull($httpTarget->refresh()->revoked_at);

        // Delivery parity: revocation reveals nothing on either transport.
        Assert::assertStringNotContainsString('shown once', $cliOutput);
        Assert::assertSame('', (string) $httpResponse->getContent());

        Assert::assertSame(
            [LifecycleEventType::Issued->value, LifecycleEventType::Revoked->value],
            $this->builtForCloudEventsFor($cliTarget->id),
        );
        Assert::assertSame(
            [LifecycleEventType::Issued->value, LifecycleEventType::Revoked->value],
            $this->builtForCloudEventsFor($httpTarget->id),
        );
    }

    /**
     * The credential's audit events as a SORTED list — two events recorded
     * in the same clock second have no deterministic order under random
     * uuids, and the parity claim is about which events exist.
     *
     * @return list<string>
     */
    private function builtForCloudEventsFor(string $credentialId): array
    {
        $events = CredentialAuditEvent::query()
            ->where('credential_id', $credentialId)
            ->pluck('event')
            ->map(static fn (mixed $event): string => $event instanceof LifecycleEventType ? $event->value : (string) $event) /** @phpstan-ignore cast.string (pluck's value shape depends on the cast) */
            ->values()
            ->all();

        sort($events);

        return $events;
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
            'subject_type',
            'subject_ref',
            'created_at',
            'updated_at',
        ];
    }
}
