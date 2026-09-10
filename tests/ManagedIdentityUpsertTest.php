<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\IssueHumanInvitation;
use ArtisanBuild\BuiltForCloud\Actions\RequestStandalonePasswordReset;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Symfony\Component\HttpKernel\Exception\HttpException;

uses(RefreshDatabase::class);

function p3bConnection(
    string $issuer = 'https://issuer.example.test',
    string $connectionId = 'connection-fixture',
): ManagedAuthConnection {
    return new ManagedAuthConnection(
        $issuer,
        $connectionId,
        'organization-fixture',
        'installation-fixture',
        7,
        'https://authority.example.test',
        'fixture-client-secret',
        null,
    );
}

function p3bExchange(
    string $subject = 'subject-fixture',
    string $email = 'fixture-member@example.test',
    string $name = 'Fixture Member',
    string $role = 'member',
): ManagedAuthExchange {
    return new ManagedAuthExchange(
        $subject,
        'membership-fixture',
        'active',
        'active',
        $role,
        $name,
        $email,
        true,
        8,
        13,
        new DateTimeImmutable('2026-09-10T12:00:00+00:00'),
    );
}

/** @return array{fixture: ManagedAuthorityFixture, state: string, nonce: string} */
function p3bBegin(): array
{
    $baseUrl = 'https://authority.example.test';
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
    $fixture = new ManagedAuthorityFixture(
        $baseUrl,
        $secret,
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
    );
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
    $response = test()->get('/bfc/managed/login');
    $response->assertRedirect();
    parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

    return [
        'fixture' => $fixture,
        'state' => $query['state'],
        'nonce' => session(ManagedHandoff::SESSION_NONCE_KEY),
    ];
}

it('moves the unknown-subject case to a distinct identity and never adopts the same-email local row', function (): void {
    $existing = User::query()->create([
        'name' => 'Existing Local Identity',
        'email' => 'fixture-member@example.test',
        'password' => 'untouched-password-hash',
    ]);
    $existing->forceFill([
        'role' => 'admin',
        'email_verified_at' => now()->subDay(),
        'original_contact_email' => 'fixture-member@example.test',
    ])->save();
    $before = $existing->fresh()->getAttributes();
    $handoff = p3bBegin();

    $response = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'unknown-subject-code',
        ]));

    $response->assertRedirect('/');
    $created = User::query()->where('scalpels_id', 'subject-fixture')->sole();
    expect(User::query()->count())->toBe(2)
        ->and($existing->fresh()->getAttributes())->toBe($before)
        ->and($created->getKey())->not->toBe($existing->getKey())
        ->and($created->email)->toBe('fixture-member+bfc@example.test')
        ->and($created->original_contact_email)->toBe('fixture-member@example.test')
        ->and($created->email_is_generated)->toBeTrue()
        ->and($created->scalpels_issuer)->toBe('https://issuer.example.test')
        ->and($created->scalpels_connection_id)->toBe('connection-fixture')
        ->and(auth('web')->id())->toBe($created->getKey());
});

it('refuses an unrecognised integrity violation through the managed callback', function (): void {
    $owner = User::query()->create([
        'name' => 'Existing Owner',
        'email' => 'owner@example.test',
    ]);
    $owner->forceFill(['role' => UserRole::Owner->value])->save();
    $handoff = p3bBegin();
    $handoff['fixture']->exchangeOverrides = ['role' => UserRole::Owner->value];

    $response = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'new-owner-subject-code',
        ]));

    $response->assertStatus(404)->assertSeeText('Not Found');
    expect(User::query()->count())->toBe(1)
        ->and(User::query()->whereNotNull('scalpels_id')->exists())->toBeFalse()
        ->and(auth('web')->check())->toBeFalse();
});

it('keys strictly on issuer connection and subject while the exact tuple converges', function (): void {
    $upsert = app(ManagedIdentityUpsert::class);
    $sameSubject = 'same-subject';

    $first = $upsert->upsert(
        p3bConnection('https://issuer-a.example.test', 'connection-a'),
        p3bExchange($sameSubject, 'first@example.test'),
    );
    $differentIssuer = $upsert->upsert(
        p3bConnection('https://issuer-b.example.test', 'connection-a'),
        p3bExchange($sameSubject, 'second@example.test'),
    );
    $differentConnection = $upsert->upsert(
        p3bConnection('https://issuer-a.example.test', 'connection-b'),
        p3bExchange($sameSubject, 'third@example.test'),
    );
    $repeat = $upsert->upsert(
        p3bConnection('https://issuer-a.example.test', 'connection-a'),
        p3bExchange($sameSubject, 'changed-source@example.test', 'Updated Name', 'admin'),
    );

    expect(User::query()->count())->toBe(3)
        ->and([$first->getKey(), $differentIssuer->getKey(), $differentConnection->getKey()])
        ->each->toBeInt()
        ->and(array_unique([$first->getKey(), $differentIssuer->getKey(), $differentConnection->getKey()]))
        ->toHaveCount(3)
        ->and($repeat->getKey())->toBe($first->getKey())
        ->and($repeat->email)->toBe('first@example.test')
        ->and($repeat->original_contact_email)->toBe('changed-source@example.test')
        ->and($repeat->name)->toBe('Updated Name')
        ->and($repeat->role)->toBe('admin');
});

it('maps only trusted active fields at the local receipt time and preserves assigned identity state', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T13:00:00+00:00');
    $connection = p3bConnection();
    $upsert = app(ManagedIdentityUpsert::class);
    $user = $upsert->upsert($connection, p3bExchange());
    $createdAt = $user->created_at?->toAtomString();
    $verifiedAt = now()->subDay();
    $user->forceFill([
        'password' => 'preserved-password-hash',
        'email_verified_at' => $verifiedAt,
        'auth_session_version' => 9,
        'status' => 'inactive',
        'deactivated_at' => now()->subHour(),
    ])->save();

    CarbonImmutable::setTestNow('2026-09-10T13:05:00+00:00');
    $updated = $upsert->upsert(
        $connection,
        p3bExchange(email: 'new-source@example.test', name: 'Mapped Name', role: 'admin'),
    );

    expect($updated->getKey())->toBe($user->getKey())
        ->and($updated->email)->toBe('fixture-member@example.test')
        ->and($updated->password)->toBe('preserved-password-hash')
        ->and($updated->email_verified_at?->toAtomString())->toBe($verifiedAt->toAtomString())
        ->and($updated->auth_session_version)->toBe(9)
        ->and($updated->created_at?->toAtomString())->toBe($createdAt)
        ->and($updated->name)->toBe('Mapped Name')
        ->and($updated->role)->toBe('admin')
        ->and($updated->status)->toBe('active')
        ->and($updated->deactivated_at)->toBeNull()
        ->and($updated->original_contact_email)->toBe('new-source@example.test')
        ->and($updated->membership_confirmed_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($updated->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($updated->membership_response_at?->toAtomString())->toBe(now()->toAtomString());
});

it('lets the normalized database key reject case-equivalent email values', function (): void {
    User::query()->create(['name' => 'First', 'email' => 'CaseSensitive@example.test']);

    expect(fn () => User::query()->create(['name' => 'Second', 'email' => 'casesensitive@example.test']))
        ->toThrow(QueryException::class);
});

it('checks every alias candidate including real plus addresses and respects email length', function (): void {
    $source = str_repeat('a', 64).'@example.test';
    User::query()->create(['name' => 'Source Holder', 'email' => $source]);
    User::query()->create([
        'name' => 'Real Plus Holder',
        'email' => str_repeat('a', 60).'+bfc@example.test',
    ]);

    $created = app(ManagedIdentityUpsert::class)->upsert(
        p3bConnection(),
        p3bExchange(email: $source),
    );

    expect($created->email)->toBe(str_repeat('a', 58).'+bfc-2@example.test')
        ->and(strlen($created->email))->toBeLessThanOrEqual(255)
        ->and(filter_var($created->email, FILTER_VALIDATE_EMAIL))->not->toBeFalse()
        ->and($created->original_contact_email)->toBe($source)
        ->and($created->email_is_generated)->toBeTrue();

    User::query()->create(['name' => 'Tagged Source Holder', 'email' => 'person+real@example.test']);
    $tagged = app(ManagedIdentityUpsert::class)->upsert(
        p3bConnection(),
        p3bExchange(subject: 'tagged-subject', email: 'person+real@example.test'),
    );
    expect($tagged->email)->toBe('person+real+bfc@example.test')
        ->and($tagged->original_contact_email)->toBe('person+real@example.test');
});

it('refuses rather than truncating into a real plus tag', function (): void {
    $source = str_repeat('a', 59).'+real@example.test';
    $holder = User::query()->create(['name' => 'Tagged Source Holder', 'email' => $source]);
    $holder->forceFill(['original_contact_email' => $source])->save();

    expect(fn () => app(ManagedIdentityUpsert::class)->upsert(
        p3bConnection(),
        p3bExchange(subject: 'long-tagged-subject', email: $source),
    ))->toThrow(ManagedAuthRefused::class);

    expect(User::query()->count())->toBe(1)
        ->and($holder->fresh()->email)->toBe($source)
        ->and($holder->fresh()->original_contact_email)->toBe($source)
        ->and(User::query()->where('email', 'like', '%++%')->exists())->toBeFalse();
});

it('preserves identity and assigned email across all source-email changes and persists conflict state', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    User::query()->create(['name' => 'Initial Holder', 'email' => 'initial@example.test']);
    $upsert = app(ManagedIdentityUpsert::class);
    $connection = p3bConnection();
    $user = $upsert->upsert($connection, p3bExchange(email: 'initial@example.test'));
    $id = $user->getKey();
    $assignedEmail = $user->email;

    $free = $upsert->upsert($connection, p3bExchange(email: 'free@example.test'));
    expect($free->getKey())->toBe($id)
        ->and($free->email)->toBe($assignedEmail)
        ->and($free->original_contact_email)->toBe('free@example.test')
        ->and($free->email_conflict_at)->toBeNull()
        ->and(User::query()->count())->toBe(2);

    User::query()->create(['name' => 'Renewed Holder', 'email' => 'renewed@example.test']);
    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    $renewed = $upsert->upsert($connection, p3bExchange(email: 'renewed@example.test'));
    expect($renewed->getKey())->toBe($id)
        ->and($renewed->email)->toBe($assignedEmail)
        ->and($renewed->original_contact_email)->toBe('renewed@example.test')
        ->and($renewed->email_conflict_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($renewed->email_conflict_source)->toBe('renewed@example.test')
        ->and(User::query()->count())->toBe(3);

    CarbonImmutable::setTestNow('2026-09-10T12:10:00+00:00');
    $cleared = $upsert->upsert($connection, p3bExchange(email: 'clear@example.test'));
    expect($cleared->getKey())->toBe($id)
        ->and($cleared->email)->toBe($assignedEmail)
        ->and($cleared->original_contact_email)->toBe('clear@example.test')
        ->and($cleared->email_conflict_at)->toBeNull()
        ->and($cleared->email_conflict_source)->toBeNull()
        ->and(User::query()->count())->toBe(3);
});

it('never resolves a generated address as a password-reset or invitation setup recipient', function (): void {
    Notification::fake();
    User::query()->create(['name' => 'Collision Holder', 'email' => 'recover@example.test']);
    $generated = app(ManagedIdentityUpsert::class)->upsert(
        p3bConnection(),
        p3bExchange(email: 'recover@example.test'),
    );
    $generated->forceFill(['email_verified_at' => now()])->save();

    app(RequestStandalonePasswordReset::class)($generated->email);
    expect(DB::table('password_reset_tokens')->where('email', $generated->email)->exists())->toBeFalse();

    $owner = User::query()->create(['name' => 'Owner', 'email' => 'owner@example.test']);
    $owner->forceFill(['role' => UserRole::Owner->value, 'email_verified_at' => now()])->save();

    expect(fn () => app(IssueHumanInvitation::class)($owner, $generated->email, UserRole::Member))
        ->toThrow(HttpException::class);
    Notification::assertNothingSent();
});
