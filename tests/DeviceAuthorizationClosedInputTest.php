<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;

final class DeviceAuthorizationClosedInputTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        DeviceFlowDeclaration::$profiles = [];
        DeviceFlowDeclaration::$authorizeCalls = 0;
        DeviceFlowDeclaration::$resolvedSubject = null;
        DeviceFlowDeclaration::$selfServiceAbilities = [];
        DeviceFlowDeclaration::$selfServiceKinds = [CredentialKind::Bearer];
        config([
            'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
            'built-for-cloud.credentials.app_purposes' => [
                'closed.device' => CredentialPurpose::Consumption->value,
                'closed.loopback' => CredentialPurpose::Consumption->value,
            ],
        ]);
    }

    #[DataProvider('invalidLoopbackAuthorizeQueries')]
    public function test_loopback_authorize_refuses_closed_input_without_effects(string $case): void
    {
        $user = $this->user('loopback-'.$case);
        $this->profile($user, 'closed.loopback');
        $this->actingAsVersioned($user, 'web');
        $valid = $this->validLoopbackQuery();

        $this->get('/bfc/loopback/authorize?'.$this->encodeQuery($valid))
            ->assertOk()
            ->assertSee('Test-created closed loopback');
        $before = $this->effectSnapshot();
        $this->assertCount(1, $before['authorizations']);
        $this->assertCount(1, $before['events']);
        $this->assertCount(1, $before['bindings']);

        $this->get('/bfc/loopback/authorize?'.$this->invalidLoopbackQuery($case, $valid))
            ->assertNotFound()
            ->assertSee('data-testid="device-authorization-unavailable"', false);

        $this->assertSame($before, $this->effectSnapshot());
    }

    #[DataProvider('malformedDeviceUserCodes')]
    public function test_device_decision_refuses_malformed_user_codes_without_effects(string $case): void
    {
        $user = $this->user('device-'.$case);
        $this->profile($user, 'closed.device');
        $this->actingAsVersioned($user, 'web');
        $start = $this->postJson('/bfc/device-authorizations', [
            'app_purpose' => 'closed.device',
            'label' => 'Test-created closed device',
        ])->assertCreated();
        $page = $this->get('/bfc/device')->assertOk()->assertSee((string) $start->json('user_code'));
        $approve = $this->hiddenInputs($page->getContent(), 'approve');
        $approve['user_code'] = $this->malformedUserCode($case, $approve['user_code']);
        $before = $this->effectSnapshot();
        $this->assertCount(1, $before['authorizations']);
        $this->assertCount(1, $before['events']);
        $this->assertCount(1, $before['bindings']);
        $this->assertCount(2, $before['submission_nonces']);

        $this->post('/bfc/device', $approve)
            ->assertNotFound()
            ->assertSee('data-testid="device-authorization-unavailable"', false);

        $this->assertSame($before, $this->effectSnapshot());
    }

    #[DataProvider('invalidPublicTokenInputs')]
    public function test_public_token_route_refuses_closed_input_before_grant_effects(string $case): void
    {
        $user = $this->user('token-'.$case);
        $this->profile($user, 'closed.device');
        $this->actingAsVersioned($user, 'web');
        $start = $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'closed.device'])->assertCreated();
        $deviceCode = (string) $start->json('device_code');
        $this->assertCount(1, app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()));

        $this->postJson('/bfc/device/token', ['device_code' => $deviceCode])
            ->assertStatus(400)
            ->assertExactJson(['error' => 'authorization_pending']);
        $before = $this->effectSnapshot();
        $this->assertCount(1, $before['authorizations']);
        $this->assertCount(1, $before['events']);
        $this->assertNotNull($before['authorizations'][0]['last_polled_at']);

        [$contentType, $body] = match ($case) {
            'duplicate-json-key' => ['application/json', '{"device_code":"'.$deviceCode.'","device_code":"'.str_repeat('z', 43).'"}'],
            'unknown-json-field' => ['application/json', json_encode(['device_code' => $deviceCode, 'unexpected' => true], JSON_THROW_ON_ERROR)],
            'list-json-field' => ['application/json', json_encode(['device_code' => [$deviceCode]], JSON_THROW_ON_ERROR)],
            'form-media-type' => ['application/x-www-form-urlencoded', 'device_code='.rawurlencode($deviceCode)],
        };

        $this->call('POST', '/bfc/device/token', server: ['CONTENT_TYPE' => $contentType], content: $body)
            ->assertStatus(400)
            ->assertExactJson(['error' => 'invalid_request']);

        $this->assertSame($before, $this->effectSnapshot());
    }

    /** @return iterable<string, array{string}> */
    public static function invalidLoopbackAuthorizeQueries(): iterable
    {
        foreach ([
            'wrong-scheme',
            'overlong-redirect',
            'control-in-redirect',
            'backslash-in-redirect',
            'wrong-host',
            'missing-port',
            'low-port',
            'high-port',
            'userinfo',
            'fragment',
            'encoded-host',
            'parser-ambiguity',
            'reserved-code',
            'reserved-error',
            'reserved-state',
            'non-s256',
            'malformed-challenge',
            'wrong-decoded-length-challenge',
            'short-state',
            'long-state',
            'malformed-state',
            'unknown-query-field',
            'duplicate-query-field',
            'list-query-field',
        ] as $case) {
            yield $case => [$case];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function malformedDeviceUserCodes(): iterable
    {
        foreach (['separator', 'internal-whitespace', 'non-ascii-lookalike', 'short', 'long'] as $case) {
            yield $case => [$case];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function invalidPublicTokenInputs(): iterable
    {
        foreach (['duplicate-json-key', 'unknown-json-field', 'list-json-field', 'form-media-type'] as $case) {
            yield $case => [$case];
        }
    }

    private function user(string $case): User
    {
        return User::query()->create([
            'name' => 'Closed input operator',
            'email' => $case.'@example.test',
            'password' => bcrypt('test-created-password'),
        ]);
    }

    private function profile(User $user, string $purpose): void
    {
        $profile = new CredentialAuthorizationProfile(
            $purpose,
            new BoundCredentialScope(
                $purpose,
                new Subject(SubjectType::UserPrincipal, 'closed-user:'.$user->getKey()),
                'closed-installation-test',
                'closed-application-test',
                'https://closed-audience.example.test',
            ),
            CredentialAuthorizationOwnership::Personal,
            [],
            now()->addDay(),
            600,
            5,
        );
        DeviceFlowDeclaration::$profiles = [$profile];
        DeviceFlowDeclaration::$resolvedSubject = $profile->scope->subject;
    }

    /** @return array<string, string> */
    private function validLoopbackQuery(): array
    {
        $verifier = str_repeat('v', 43);

        return [
            'app_purpose' => 'closed.loopback',
            'redirect_uri' => 'http://127.0.0.1:49152/closed',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            'state' => str_repeat('s', 32),
            'label' => 'Test-created closed loopback',
        ];
    }

    /** @param array<string, string> $valid */
    private function invalidLoopbackQuery(string $case, array $valid): string
    {
        if ($case === 'duplicate-query-field') {
            return $this->encodeQuery($valid).'&state='.str_repeat('d', 32);
        }

        if ($case === 'list-query-field') {
            return $this->encodeQuery($valid).'&extra%5B%5D=value';
        }

        $invalid = $valid;

        match ($case) {
            'wrong-scheme' => $invalid['redirect_uri'] = 'https://127.0.0.1:49152/closed',
            'overlong-redirect' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/'.str_repeat('a', 2050),
            'control-in-redirect' => $invalid['redirect_uri'] = "http://127.0.0.1:49152/closed\npath",
            'backslash-in-redirect' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/closed\\path',
            'wrong-host' => $invalid['redirect_uri'] = 'http://example.test:49152/closed',
            'missing-port' => $invalid['redirect_uri'] = 'http://127.0.0.1/closed',
            'low-port' => $invalid['redirect_uri'] = 'http://127.0.0.1:1023/closed',
            'high-port' => $invalid['redirect_uri'] = 'http://127.0.0.1:65536/closed',
            'userinfo' => $invalid['redirect_uri'] = 'http://user@127.0.0.1:49152/closed',
            'fragment' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/closed#fragment',
            'encoded-host' => $invalid['redirect_uri'] = 'http://%31%32%37.0.0.1:49152/closed',
            'parser-ambiguity' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152@evil.example/closed',
            'reserved-code' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/closed?code=reserved',
            'reserved-error' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/closed?error=reserved',
            'reserved-state' => $invalid['redirect_uri'] = 'http://127.0.0.1:49152/closed?state=reserved',
            'non-s256' => $invalid['code_challenge_method'] = 'plain',
            'malformed-challenge' => $invalid['code_challenge'] = str_repeat('*', 43),
            'wrong-decoded-length-challenge' => $invalid['code_challenge'] = str_repeat('A', 42),
            'short-state' => $invalid['state'] = str_repeat('s', 31),
            'long-state' => $invalid['state'] = str_repeat('s', 129),
            'malformed-state' => $invalid['state'] = str_repeat('s', 31).'!',
            'unknown-query-field' => $invalid['unexpected'] = 'value',
        };

        return $this->encodeQuery($invalid);
    }

    private function malformedUserCode(string $case, string $valid): string
    {
        $compact = str_replace('-', '', $valid);

        return match ($case) {
            'separator' => substr($compact, 0, 4).':'.substr($compact, 4),
            'internal-whitespace' => substr($compact, 0, 4).' '.substr($compact, 4),
            'non-ascii-lookalike' => "\u{0410}".substr($valid, 1),
            'short' => substr($valid, 0, -1),
            'long' => $valid.'A',
        };
    }

    /** @param array<string, string> $parameters */
    private function encodeQuery(array $parameters): string
    {
        return http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /** @return array<string, string> */
    private function hiddenInputs(string $html, string $action): array
    {
        preg_match('/<form[^>]*>.*?name="action" value="'.preg_quote($action, '/').'".*?<\/form>/s', $html, $form);
        preg_match_all('/name="([^"]+)" value="([^"]*)"/', $form[0] ?? '', $inputs, PREG_SET_ORDER);

        return array_column($inputs, 2, 1);
    }

    /** @return array<string, mixed> */
    private function effectSnapshot(): array
    {
        $currentRequest = request();

        return [
            'authorizations' => $this->tableSnapshot('credential_authorizations'),
            'events' => $this->tableSnapshot('credential_audit_events'),
            'credentials' => $this->tableSnapshot('credentials'),
            'submission_nonces' => $this->tableSnapshot('bfc_submission_nonces'),
            'bindings' => $currentRequest->hasSession()
                ? app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts($currentRequest)
                : null,
            'authorization_calls' => DeviceFlowDeclaration::$authorizeCalls,
        ];
    }

    /** @return list<array<string, mixed>> */
    private function tableSnapshot(string $table): array
    {
        return DB::table($table)->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all();
    }
}
