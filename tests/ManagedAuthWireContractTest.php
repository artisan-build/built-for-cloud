<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthHighWater;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

/** @return array{baseUrl: string, secret: string, fixture: ManagedAuthorityFixture} */
function wireConnection(): array
{
    $baseUrl = 'https://wire-authority.example.test';
    $secret = bin2hex(random_bytes(32));
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => $baseUrl,
    ]);
    config(['built-for-cloud.managed.client_secret' => $secret]);

    return [
        'baseUrl' => $baseUrl,
        'secret' => $secret,
        'fixture' => new ManagedAuthorityFixture(
            $baseUrl,
            $secret,
            'https://issuer.example.test',
            'connection-fixture',
            'organization-fixture',
            'installation-fixture',
            7,
        ),
    ];
}

/** @return array{state: string, nonce: string} */
function wireBegin(ManagedAuthorityFixture $fixture): array
{
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
    $response = test()->get('/bfc/managed/login');
    $response->assertRedirect();
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

    return [
        'state' => $query['state'],
        'nonce' => session(ManagedHandoff::SESSION_NONCE_KEY),
    ];
}

function wireUser(): User
{
    $user = User::query()->create([
        'name' => 'Wire Member',
        'email' => 'wire-member@example.test',
    ]);
    $user->forceFill([
        'role' => 'member',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'subject-fixture',
    ])->save();

    return $user;
}

it('makes both fixture legs conform to the frozen request and response tables', function (): void {
    ['fixture' => $fixture] = wireConnection();
    wireUser();
    $handoff = wireBegin($fixture);
    $response = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'fixture-code',
        ]));
    $response->assertRedirect('/');

    expect($fixture->calls)->toHaveCount(2)
        ->and($fixture->calls[0]['method'])->toBe('POST')
        ->and($fixture->calls[0]['path'])->toBe('/managed-auth/v1/handoffs')
        ->and(array_keys($fixture->calls[0]['body']))->toBe([
            'connection_id', 'installation_id', 'request_id',
        ])
        ->and($fixture->calls[1]['method'])->toBe('POST')
        ->and($fixture->calls[1]['path'])->toBe('/managed-auth/v1/handoffs/'.$handoff['state'].'/exchange')
        ->and(array_keys($fixture->calls[1]['body']))->toBe([
            'connection_id', 'installation_id', 'code',
        ])
        ->and(array_keys($fixture->binding()))->toBe([
            'contract_version',
            'issuer',
            'connection_id',
            'organization_id',
            'installation_id',
            'authority_generation',
            'roster_version',
            'response_sequence',
            'responded_at',
        ]);
});

it('refuses every missing, null, and mistyped required handoff response field', function (string $field, string $shape, mixed $replacement): void {
    ['fixture' => $fixture] = wireConnection();
    $fixture->handoffTransform = static function (array $payload) use ($field, $shape, $replacement): array {
        if ($shape === 'missing') {
            unset($payload[$field]);
        } else {
            $payload[$field] = $replacement;
        }

        return $payload;
    };
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));

    $this->get('/bfc/managed/login')->assertStatus(404)->assertSeeText('Not Found');
    expect(DB::table('bfc_managed_handoffs')->count())->toBe(0);
})->with((static function (): array {
    $types = [
        'contract_version' => 1,
        'request_id' => 1,
        'authorization_url' => [],
        'expires_at' => 1,
    ];
    $cases = [];

    foreach ($types as $field => $mistyped) {
        $cases[$field.' missing'] = [$field, 'missing', null];
        $cases[$field.' null'] = [$field, 'null', null];
        $cases[$field.' mistyped'] = [$field, 'mistyped', $mistyped];
    }

    return $cases;
})());

it('refuses every missing, null, and mistyped required exchange response field before effects', function (string $field, string $shape, mixed $replacement): void {
    ['fixture' => $fixture] = wireConnection();
    $user = wireUser();
    $handoff = wireBegin($fixture);
    $fixture->exchangeTransform = static function (array $payload) use ($field, $shape, $replacement): array {
        if ($shape === 'missing') {
            unset($payload[$field]);
        } else {
            $payload[$field] = $replacement;
        }

        return $payload;
    };
    $before = $user->fresh()->toArray();

    $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'fixture-code',
        ]))
        ->assertStatus(404)
        ->assertSeeText('Not Found');

    expect($user->fresh()->toArray())->toBe($before)
        ->and(auth('web')->check())->toBeFalse()
        ->and(session(StandaloneAccess::SESSION_VERSION_KEY))->toBeNull();
})->with((static function (): array {
    $types = [
        'contract_version' => 1,
        'issuer' => 1,
        'connection_id' => 1,
        'organization_id' => 1,
        'installation_id' => 1,
        'authority_generation' => '7',
        'roster_version' => '8',
        'response_sequence' => '13',
        'responded_at' => 1,
        'scalpels_id' => 1,
        'membership_id' => 1,
        'membership_status' => 1,
        'connection_status' => 1,
        'role' => 1,
        'display_name' => [],
        'contact_email' => 1,
        'contact_email_verified' => 'true',
    ];
    $cases = [];

    foreach ($types as $field => $mistyped) {
        $cases[$field.' missing'] = [$field, 'missing', null];
        $cases[$field.' null'] = [$field, 'null', null];
        $cases[$field.' mistyped'] = [$field, 'mistyped', $mistyped];
    }

    return $cases;
})());

it('refuses unknown contract versions on both successful legs', function (string $leg): void {
    ['fixture' => $fixture] = wireConnection();

    if ($leg === 'handoff') {
        $fixture->handoffTransform = static fn (array $payload): array => array_merge(
            $payload,
            ['contract_version' => 'managed-auth-v2'],
        );
        Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
        $this->get('/bfc/managed/login')->assertStatus(404);

        return;
    }

    wireUser();
    $handoff = wireBegin($fixture);
    $fixture->exchangeOverrides = ['contract_version' => 'managed-auth-v2'];
    $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'fixture-code',
        ]))
        ->assertStatus(404);
})->with(['handoff', 'exchange']);

it('refuses every frozen failure mapping, unlisted error, absent version, and malformed body', function (int $status, mixed $body): void {
    wireConnection();
    Http::fake(Http::response($body, $status));

    $this->get('/bfc/managed/login')->assertStatus(404)->assertSeeText('Not Found');
    expect(DB::table('bfc_managed_handoffs')->count())->toBe(0);
})->with([
    'invalid grant' => [400, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'invalid_grant']],
    'unsupported version' => [400, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'unsupported_contract_version']],
    'invalid client' => [401, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'invalid_client']],
    'rate limited' => [429, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'rate_limited']],
    'server error 500' => [500, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'server_error']],
    'server error 503' => [503, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'server_error']],
    'unlisted error' => [418, ['contract_version' => ManagedAuthClient::CONTRACT_VERSION, 'error' => 'unlisted']],
    'failure without version' => [500, ['error' => 'server_error']],
    'malformed body' => [500, 'not-json'],
]);

it('compares order fields monotonically and independently against both dimensions', function (string $dimension, int $roster, int $sequence, bool $accepted): void {
    ['fixture' => $fixture] = wireConnection();
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
    $subject = $dimension === 'subject' ? new ManagedAuthHighWater(8, 13) : null;
    $connection = $dimension === 'connection' ? new ManagedAuthHighWater(8, 13) : null;
    $fixture->exchangeOverrides = [
        'roster_version' => $roster,
        'response_sequence' => $sequence,
    ];

    $run = fn () => app(ManagedAuthClient::class)->exchange(
        ManagedAuthConnection::current(),
        str_repeat('A', 43),
        'fixture-code',
        $subject,
        $connection,
    );

    if ($accepted) {
        expect($run()->responseSequence)->toBe($sequence);
    } else {
        expect($run)->toThrow(ManagedAuthRefused::class);
    }
})->with([
    ['subject', 8, 13, true],
    ['subject', 7, 13, false],
    ['subject', 8, 12, false],
    ['connection', 8, 13, true],
    ['connection', 7, 13, false],
    ['connection', 8, 12, false],
]);
