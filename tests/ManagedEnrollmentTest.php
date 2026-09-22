<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedClientSecretStore;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaimMinter;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, DetectsSecretLeaks::class, ContractAssertions::class);

/** @return array<string, mixed> */
function p1EnrollmentPayload(array $overrides = []): array
{
    return array_replace([
        'enrolment_id' => (string) Str::uuid(),
        'expected_generation' => 1,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_base_url' => 'https://transition-authority.example.test',
        'managed_client_secret' => 'transition-secret',
        'client_secret_generation' => 1,
    ], $overrides);
}

/** @return array{Authorization: string} */
function p1OwnerHeaders(string $ownerToken): array
{
    return ['Authorization' => 'Bearer '.$ownerToken];
}

function p1ClaimOwner(): string
{
    [$claimToken] = app(OwnershipClaimMinter::class)->mint();
    $claim = test()->postJson('/bfc/ownership/claim', ['token' => $claimToken])->assertCreated();

    return (string) $claim->json('owner_token');
}

/** @param array<string, mixed> $payload */
function p1Enroll(string $ownerToken, array $payload): TestResponse
{
    return test()->postJson('/bfc/managed/enrolment', $payload, p1OwnerHeaders($ownerToken));
}

/** @return array<string, mixed> */
function p1AuthorityRow(): array
{
    return (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->sole();
}

/** @param array<string, mixed> $payload */
function p1RotationPayload(array $payload, array $overrides = []): array
{
    return array_replace([
        'rotation_id' => (string) Str::uuid(),
        'issuer' => $payload['issuer'],
        'connection_id' => $payload['connection_id'],
        'installation_id' => $payload['installation_id'],
        'expected_generation' => 2,
        'expected_client_secret_generation' => 1,
        'managed_client_secret' => 'replacement-transition-secret',
    ], $overrides);
}

/** @param array<string, mixed> $payload */
function p1DisconnectPayload(array $payload, array $overrides = []): array
{
    return array_replace([
        'disconnect_id' => (string) Str::uuid(),
        'issuer' => $payload['issuer'],
        'connection_id' => $payload['connection_id'],
        'installation_id' => $payload['installation_id'],
        'expected_generation' => 2,
    ], $overrides);
}

function p1ActiveTransition(): void
{
    $body = json_encode([
        'connection_id' => 'blocked-connection',
        'installation_id' => 'blocked-installation',
        'direction' => 'adopt',
        'transition_request_id' => 'blocked-request',
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

    ManagedTransition::createActive([
        'id' => (string) Str::uuid(),
        'initiated_by_user_id' => 'blocked-user',
        'direction' => ManagedTransitionDirection::Adopt,
        'status' => ManagedTransitionStatus::Preparing,
        'issuer' => 'https://blocked-issuer.example.test',
        'connection_id' => 'blocked-connection',
        'organization_id' => 'blocked-organization',
        'installation_id' => 'blocked-installation',
        'authority_base_url' => 'https://blocked-authority.example.test',
        'authority_ca_bundle' => null,
        'client_credential_reference' => 'built-for-cloud.managed.client_secret',
        'mode_before' => AuthorityMode::Standalone,
        'mode_after' => AuthorityMode::Managed,
        'generation_before' => 1,
        'generation_after' => 2,
        'transition_request_id' => 'blocked-request',
        'prepare_request_body' => $body,
        'prepare_body_digest' => hash('sha256', $body),
    ]);
}

/** @return array{string, array<string, mixed>, User, ManagedTransitionAuthorityFixture} */
function p1PendingDisconnectFixture(): array
{
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    $owner = User::query()->create([
        'name' => 'Pending Disconnect Owner',
        'email' => 'pending-disconnect@example.test',
    ]);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $owner->email,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'pending-disconnect-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'pending-disconnect-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Pending Disconnect Owner',
        'contact_email' => 'pending-disconnect@example.test',
        'contact_email_verified' => true,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    return [$ownerToken, $enrolment, $owner->refresh(), $fixture];
}

it('atomically enrols a pristine claimed installation at generation two without leaking its secret', function (): void {
    $ownerToken = p1ClaimOwner();
    $payload = p1EnrollmentPayload();
    $secret = (string) $payload['managed_client_secret'];

    $response = $this->assertNoSecretLeakage(
        $secret,
        fn (): TestResponse => p1Enroll($ownerToken, $payload),
    );

    $response->assertCreated()
        ->assertJsonPath('enrolment_id', $payload['enrolment_id'])
        ->assertJsonPath('mode', 'managed')
        ->assertJsonPath('generation', 2)
        ->assertJsonPath('client_secret_generation', 1)
        ->assertJsonStructure(['enrolment_id', 'mode', 'generation', 'client_secret_generation', 'enrolled_at']);
    expect($response->headers->get('Cache-Control'))->toContain('no-store');
    $this->assertResponseCarriesNoSecret($response, $secret);

    expect(p1AuthorityRow())->toMatchArray([
        'mode' => 'managed',
        'generation' => 2,
        'issuer' => $payload['issuer'],
        'connection_id' => $payload['connection_id'],
        'organization_id' => $payload['organization_id'],
        'installation_id' => $payload['installation_id'],
        'authority_base_url' => $payload['authority_base_url'],
    ]);
});

it('replays an exact enrolment without mutation and rejects a changed secret or binding under the same id', function (): void {
    $ownerToken = p1ClaimOwner();
    $payload = p1EnrollmentPayload();
    $created = p1Enroll($ownerToken, $payload)->assertCreated();
    $committed = p1AuthorityRow();

    p1Enroll($ownerToken, $payload)
        ->assertOk()
        ->assertExactJson($created->json());
    expect(p1AuthorityRow())->toBe($committed);

    p1Enroll($ownerToken, [...$payload, 'managed_client_secret' => 'different-retry-secret'])
        ->assertStatus(409)
        ->assertJsonPath('error', 'binding_conflict');
    expect(p1AuthorityRow())->toBe($committed);

    p1Enroll($ownerToken, [...$payload, 'organization_id' => 'crossed-organization'])
        ->assertStatus(409)
        ->assertJsonPath('error', 'binding_conflict');
    expect(p1AuthorityRow())->toBe($committed);
});

it('admits only the current ownership-linked bearer', function (string $credential): void {
    $ownerToken = p1ClaimOwner();
    $headers = match ($credential) {
        'missing' => [],
        'invalid' => p1OwnerHeaders('invalid-owner-token'),
        'revoked owner' => (function () use ($ownerToken): array {
            Credential::query()->whereKey(Ownership::current()?->owner_credential_id)->update(['revoked_at' => now()]);

            return p1OwnerHeaders($ownerToken);
        })(),
        'different admin' => p1OwnerHeaders(auditOperatorCredential(
            'not-current-owner',
            [OperatorAbility::Admin->value],
        )),
    };

    $response = $this->postJson('/bfc/managed/enrolment', p1EnrollmentPayload(), $headers);

    $credential === 'different admin'
        ? $response->assertForbidden()
        : $response->assertUnauthorized();
    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(1);
})->with(['missing', 'invalid', 'revoked owner', 'different admin']);

it('refuses non-pristine, stale, already-managed, and transition-active enrolment without a partial authority write', function (string $conflict): void {
    $ownerToken = p1ClaimOwner();
    $payload = p1EnrollmentPayload();

    if ($conflict === 'non-pristine') {
        User::query()->create(['name' => 'Existing User', 'email' => 'existing@example.test']);
    } elseif ($conflict === 'generation mismatch') {
        $payload['expected_generation'] = 2;
    } elseif ($conflict === 'already managed') {
        p1Enroll($ownerToken, $payload)->assertCreated();
    } else {
        p1ActiveTransition();
    }
    $before = p1AuthorityRow();

    p1Enroll($ownerToken, [...$payload, 'enrolment_id' => (string) Str::uuid()])->assertStatus(409);

    expect(p1AuthorityRow())->toBe($before);
})->with(['non-pristine', 'generation mismatch', 'already managed', 'active transition']);

it('increments only the independent client-secret counter during replay-safe rotation', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    $rotation = p1RotationPayload($enrolment);
    $replacement = (string) $rotation['managed_client_secret'];

    $rotated = $this->assertNoSecretLeakage($replacement, fn (): TestResponse => $this->postJson(
        '/bfc/managed/enrolment/client-secret',
        $rotation,
        p1OwnerHeaders($ownerToken),
    ));

    $rotated->assertOk()
        ->assertJsonPath('rotation_id', $rotation['rotation_id'])
        ->assertJsonPath('mode', 'managed')
        ->assertJsonPath('generation', 2)
        ->assertJsonPath('client_secret_generation', 2)
        ->assertJsonStructure(['rotation_id', 'mode', 'generation', 'client_secret_generation', 'rotated_at']);
    $this->assertResponseCarriesNoSecret($rotated, $replacement);
    expect(InstallationAuthority::current()->generation)->toBe(2);

    $this->postJson('/bfc/managed/enrolment/client-secret', $rotation, p1OwnerHeaders($ownerToken))
        ->assertOk()
        ->assertExactJson($rotated->json());
    expect(InstallationAuthority::current()->generation)->toBe(2);

    $this->postJson('/bfc/managed/enrolment/client-secret', [
        ...$rotation,
        'rotation_id' => (string) Str::uuid(),
        'expected_client_secret_generation' => 1,
        'managed_client_secret' => 'stale-rotation-secret',
    ], p1OwnerHeaders($ownerToken))->assertStatus(409);
    expect(InstallationAuthority::current()->generation)->toBe(2);
});

it('binds rotation and disconnect to the stored issuer as well as connection and installation', function (string $route): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    $payload = $route === 'rotation'
        ? p1RotationPayload($enrolment, ['issuer' => 'https://crossed-issuer.example.test'])
        : p1DisconnectPayload($enrolment, ['issuer' => 'https://crossed-issuer.example.test']);
    $before = p1AuthorityRow();

    $this->postJson(
        $route === 'rotation'
            ? '/bfc/managed/enrolment/client-secret'
            : '/bfc/managed/enrolment/disconnect',
        $payload,
        p1OwnerHeaders($ownerToken),
    )->assertStatus(409);

    expect(p1AuthorityRow())->toBe($before)
        ->and(ManagedTransition::query()->count())->toBe(0);
})->with(['rotation', 'disconnect']);

it('contains the secret across every watched sink and the response when validation refuses it', function (): void {
    $ownerToken = p1ClaimOwner();
    $secret = 'validation-canary-secret-'.bin2hex(random_bytes(8));

    $response = $this->assertNoSecretLeakage($secret, fn (): TestResponse => p1Enroll($ownerToken, p1EnrollmentPayload([
        'managed_client_secret' => $secret,
        'unexpected_field' => 'refuse-me',
    ])));

    $response->assertUnprocessable();
    $this->assertResponseCarriesNoSecret($response, $secret);
});

it('uses the persisted enrolled secret instead of the legacy environment fallback', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    config(['built-for-cloud.managed.client_secret' => 'wrong-legacy-fallback-secret']);

    $fixture = new ManagedAuthorityFixture(
        'https://transition-authority.example.test',
        'transition-secret',
        'https://issuer.example.test',
        'transition-connection',
        'transition-organization',
        'transition-installation',
        2,
    );
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    $this->get('/bfc/managed/login')->assertRedirect();
});

it('disconnects through the existing exit transition cleanup and leaves a recoverable standalone owner', function (): void {
    config(['session.driver' => 'database', 'session.table' => 'sessions']);
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();

    $owner = User::query()->create([
        'name' => 'Managed Owner',
        'email' => 'managed-owner@example.test',
        'password' => Hash::make('managed-owner-password'),
    ]);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $owner->email,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'managed-owner',
    ])->save();
    $member = User::query()->create([
        'name' => 'Managed Member',
        'email' => 'managed-member@example.test',
        'password' => Hash::make('managed-member-password'),
    ]);
    $member->forceFill(['role' => 'member', 'status' => 'active'])->save();

    foreach ([$owner, $member] as $index => $user) {
        DB::table('sessions')->insert([
            'id' => 'managed-enrolment-session-'.$index,
            'user_id' => $user->getKey(),
            'payload' => 'session-'.$index,
            'last_activity' => 1,
        ]);
        Credential::factory()->forUser((string) $user->getKey())->create(['name' => 'managed-enrolment-'.$index]);
    }
    DB::table('password_reset_tokens')->insert([
        'email' => $owner->email,
        'token' => hash('sha256', 'pre-disconnect-reset'),
        'created_at' => now(),
    ]);

    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'managed-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Managed Owner',
        'contact_email' => 'managed-owner@example.test',
        'contact_email_verified' => true,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    )->assertOk()
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3)
        ->assertJsonStructure(['disconnect_id', 'mode', 'generation', 'disconnected_at']);

    expect(array_column($fixture->calls, 'leg'))->toBe(['T1', 'T2', 'T3', 'T4'])
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(3)
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(Credential::query()->whereNotNull('user_id')->whereNull('revoked_at')->count())->toBe(0)
        // Exit PRESERVES local passwords — the standalone owner logs in
        // with hers; only adopt nulls them (the authority replaces local
        // auth on the way IN, not on the way out).
        ->and($owner->refresh()->password)->not->toBeNull()
        ->and(StandaloneAccess::userCanAuthenticate($owner->refresh()))->toBeTrue()
        ->and(StandaloneAccess::userCanReceiveRecovery($owner->refresh()))->toBeTrue()
        ->and($member->refresh()->password)->not->toBeNull()
        ->and(p1AuthorityRow())->toMatchArray([
            'issuer' => null,
            'connection_id' => null,
            'organization_id' => null,
            'installation_id' => null,
            'authority_base_url' => null,
        ]);
});

it('rolls back disconnect when the exit mapping cannot leave an accessible owner', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    $owner = User::query()->create(['name' => 'Unreachable Owner', 'email' => 'unreachable@example.test']);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'unreachable-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'unreachable-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Unreachable Owner',
        'contact_email' => 'unreachable@example.test',
        'contact_email_verified' => false,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    )->assertStatus(409);

    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Managed)
        ->and(InstallationAuthority::current()->generation)->toBe(2)
        ->and($owner->refresh()->status)->toBe('active');
});

it('refuses disconnect with 409 owner_not_accessible from the authority roster, authority unchanged and the transition durably abandoned, when the single roster Owner is not accessible', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();

    // Managed from birth: the local Owner has no password and no local
    // email verification — the ROSTER's verification of her address is
    // the only thing that could make her reachable. One roster Owner,
    // unverified there.
    $owner = User::query()->create(['name' => 'Unverified Owner', 'email' => 'unverified-owner@example.test']);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => null,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'unverified-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'unverified-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Unverified Owner',
        'contact_email' => 'unverified-owner@example.test',
        'contact_email_verified' => false,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));
    $before = p1AuthorityRow();

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    )->assertStatus(409)
        ->assertJsonPath('error', 'owner_not_accessible')
        ->assertJsonPath('reason', 'owner_not_accessible');

    // The ROSTER drove the refusal — prepare, roster fetch and staging
    // all ran before the commit guard refused, then the same legs the
    // Owner abandon route walks (state check, abandon) retired the row.
    expect(array_column($fixture->calls, 'leg'))->toBe(['T1', 'T2', 'T3', 'T5', 'T7'])
        ->and(p1AuthorityRow())->toBe($before)
        // The contract promise: no transition row is left ACTIVE — the
        // refused row is durably abandoned, not deleted and not stuck.
        ->and(ManagedTransition::query()->count())->toBe(1)
        ->and(ManagedTransition::query()->value('status'))->toBe(ManagedTransitionStatus::Abandoned);
});

it('refuses disconnect with 409 owner_not_accessible from the authority roster when it carries two active Owners and neither is accessible', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();

    // Two active Owners live on the ROSTER (two local owner rows are
    // impossible — the owner slot is unique), and neither is
    // accessible: both contact emails are unverified, and the only
    // local Owner has neither password nor local verification.
    $owner = User::query()->create(['name' => 'First Roster Owner', 'email' => 'first-roster-owner@example.test']);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => null,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'first-roster-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [
        [
            'scalpels_id' => 'first-roster-owner',
            'membership_status' => 'active',
            'role' => 'owner',
            'display_name' => 'First Roster Owner',
            'contact_email' => 'first-roster-owner@example.test',
            'contact_email_verified' => false,
        ],
        [
            'scalpels_id' => 'second-roster-owner',
            'membership_status' => 'active',
            'role' => 'owner',
            'display_name' => 'Second Roster Owner',
            'contact_email' => 'second-roster-owner@example.test',
            'contact_email_verified' => false,
        ],
    ]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));
    $before = p1AuthorityRow();

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    )->assertStatus(409)
        ->assertJsonPath('error', 'owner_not_accessible')
        ->assertJsonPath('reason', 'owner_not_accessible');

    expect(array_column($fixture->calls, 'leg'))->toBe(['T1', 'T2', 'T3', 'T5', 'T7'])
        ->and(p1AuthorityRow())->toBe($before)
        ->and(ManagedTransition::query()->count())->toBe(1)
        ->and(ManagedTransition::query()->value('status'))->toBe(ManagedTransitionStatus::Abandoned);
});

it('returns durable pending state and resumes the same disconnect through acknowledgement', function (): void {
    [$ownerToken, $enrolment, , $fixture] = p1PendingDisconnectFixture();
    $disconnect = p1DisconnectPayload($enrolment);
    $fixture->crashBeforeExecution = 'T4';

    $pending = $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        $disconnect,
        p1OwnerHeaders($ownerToken),
    );

    $pending->assertAccepted()
        ->assertJsonPath('disconnect_id', $disconnect['disconnect_id'])
        ->assertJsonPath('status', 'pending')
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3)
        ->assertJsonPath('phase', 'acknowledging')
        ->assertJsonStructure(['disconnect_id', 'transition_id', 'mode', 'generation', 'phase']);
    $transitionId = $pending->json('transition_id');
    expect($transitionId)->toBeString()->not->toBeEmpty()
        ->and(ManagedTransition::query()->whereKey($transitionId)->value('status'))
        ->toBe(ManagedTransitionStatus::Acknowledging);

    $fixture->crashBeforeExecution = null;
    $completed = $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        $disconnect,
        p1OwnerHeaders($ownerToken),
    );

    $completed->assertOk()
        ->assertJsonPath('disconnect_id', $disconnect['disconnect_id'])
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3);
    expect(ManagedTransition::query()->whereKey($transitionId)->value('status'))
        ->toBe(ManagedTransitionStatus::Acknowledged);
});

it('retains enrolment idempotency history after disconnect and requires a fresh enrolment id', function (): void {
    [$ownerToken, $enrolment] = p1PendingDisconnectFixture();

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    )->assertOk();

    User::query()->delete();
    $replay = [...$enrolment, 'expected_generation' => 3];
    p1Enroll($ownerToken, $replay)->assertStatus(409);

    p1Enroll($ownerToken, [
        ...$replay,
        'enrolment_id' => (string) Str::uuid(),
        'managed_client_secret' => 'fresh-re-enrolment-secret',
    ])->assertCreated()
        ->assertJsonPath('mode', 'managed')
        ->assertJsonPath('generation', 4)
        ->assertJsonPath('client_secret_generation', 1);
});

it('refuses an abandoned disconnect retry whose facts predate a later disconnect and re-adoption, without mutating anything', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();
    p1Enroll($ownerToken, $enrolment)->assertCreated();

    // The A1 abandoned state: one roster Owner whose contact email the
    // roster does not verify refuses the commit guard, leaving an
    // uncommitted ledger row linked to a durably Abandoned transition.
    $owner = User::query()->create(['name' => 'Blocked Owner', 'email' => 'blocked-owner@example.test']);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => null,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'blocked-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2);
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'blocked-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Blocked Owner',
        'contact_email' => 'blocked-owner@example.test',
        'contact_email_verified' => false,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    $abandoned = p1DisconnectPayload($enrolment);
    $this->postJson('/bfc/managed/enrolment/disconnect', $abandoned, p1OwnerHeaders($ownerToken))
        ->assertStatus(409)
        ->assertJsonPath('error', 'owner_not_accessible');
    expect(ManagedTransition::query()->count())->toBe(1)
        ->and(ManagedTransition::query()->value('status'))->toBe(ManagedTransitionStatus::Abandoned);
    $abandonedTransitionId = (string) ManagedTransition::query()->value('id');

    // The supported lifecycle moves on: the roster records the Owner's
    // address as verified, a DIFFERENT disconnect completes, and a fresh
    // enrolment re-adopts the installation under a different binding.
    $fixture->rosterPages['NULL'][0]['contact_email_verified'] = true;

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment, ['disconnect_id' => (string) Str::uuid()]),
        p1OwnerHeaders($ownerToken),
    )->assertOk();
    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone);

    User::query()->delete();
    p1Enroll($ownerToken, p1EnrollmentPayload([
        'issuer' => 'https://later-issuer.example.test',
        'connection_id' => 'later-connection',
        'organization_id' => 'later-organization',
        'installation_id' => 'later-installation',
        'authority_base_url' => 'https://later-authority.example.test',
        'managed_client_secret' => 'later-lifecycle-secret',
        'expected_generation' => 3,
    ]))->assertCreated()->assertJsonPath('generation', 4);

    // A live local Owner must exist so the refusal below comes from the
    // revalidation, not the actor gate.
    $owner = User::query()->create(['name' => 'Later Owner', 'email' => 'later-owner@example.test']);
    $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();

    $before = p1AuthorityRow();
    $transitionsBefore = ManagedTransition::query()->count();
    $legsBefore = count($fixture->calls);

    // Retrying the OLD id must not exit the newer binding: bounded 409,
    // no fresh transition, no authority legs, no ledger re-point.
    $this->postJson('/bfc/managed/enrolment/disconnect', $abandoned, p1OwnerHeaders($ownerToken))
        ->assertStatus(409)
        ->assertJsonPath('error', 'binding_conflict')
        ->assertJsonPath('reason', 'binding_conflict');

    expect(p1AuthorityRow())->toBe($before)
        ->and(ManagedTransition::query()->count())->toBe($transitionsBefore)
        ->and(count($fixture->calls))->toBe($legsBefore)
        ->and((array) DB::table('bfc_managed_enrolment_requests')->where('id', $abandoned['disconnect_id'])->sole())->toMatchArray([
            'committed_response' => null,
            'managed_transition_id' => $abandonedTransitionId,
        ]);
});

it('accepts a 255-character issuer and refuses a 256-character issuer on every managed enrolment route', function (): void {
    $ownerToken = p1ClaimOwner();

    // 27-char origin + 114 × "/x" = exactly the 255-character persistence width.
    $issuer255 = 'https://issuer.example.test'.str_repeat('/x', 114);
    $issuer256 = $issuer255.'x';
    expect(strlen($issuer255))->toBe(255)->and(strlen($issuer256))->toBe(256);
    $before = p1AuthorityRow();

    p1Enroll($ownerToken, p1EnrollmentPayload(['issuer' => $issuer256]))
        ->assertUnprocessable();
    expect(p1AuthorityRow())->toBe($before)
        ->and(DB::table('bfc_managed_enrolment_requests')->count())->toBe(0);

    $enrolment = p1EnrollmentPayload(['issuer' => $issuer255]);
    p1Enroll($ownerToken, $enrolment)->assertCreated();
    expect(p1AuthorityRow()['issuer'])->toBe($issuer255)
        ->and(DB::table('bfc_managed_enrolment_requests')->where('id', $enrolment['enrolment_id'])->value('issuer'))->toBe($issuer255);

    $this->postJson(
        '/bfc/managed/enrolment/client-secret',
        p1RotationPayload($enrolment, ['issuer' => $issuer256]),
        p1OwnerHeaders($ownerToken),
    )->assertUnprocessable();

    $this->postJson(
        '/bfc/managed/enrolment/disconnect',
        p1DisconnectPayload($enrolment, ['issuer' => $issuer256]),
        p1OwnerHeaders($ownerToken),
    )->assertUnprocessable();

    expect(p1AuthorityRow()['issuer'])->toBe($issuer255);
});

it('matches the documented metadata shapes on real enrolment, rotation and disconnect responses', function (): void {
    $ownerToken = p1ClaimOwner();
    $enrolment = p1EnrollmentPayload();

    $created = p1Enroll($ownerToken, $enrolment);
    $created->assertCreated();
    $this->assertBuiltForCloudMetadataEndpoint($created, 'POST /bfc/managed/enrolment');

    $rotated = $this->postJson(
        '/bfc/managed/enrolment/client-secret',
        p1RotationPayload($enrolment),
        p1OwnerHeaders($ownerToken),
    );
    $rotated->assertOk();
    $this->assertBuiltForCloudMetadataEndpoint($rotated, 'POST /bfc/managed/enrolment/client-secret');

    $owner = User::query()->create(['name' => 'Metadata Owner', 'email' => 'metadata-owner@example.test']);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $owner->email,
        'scalpels_issuer' => $enrolment['issuer'],
        'scalpels_connection_id' => $enrolment['connection_id'],
        'scalpels_id' => 'metadata-owner',
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: 2, clientSecret: 'replacement-transition-secret');
    $fixture->rosterPages = ['NULL' => [[
        'scalpels_id' => 'metadata-owner',
        'membership_status' => 'active',
        'role' => 'owner',
        'display_name' => 'Metadata Owner',
        'contact_email' => 'metadata-owner@example.test',
        'contact_email_verified' => true,
    ]]];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    $disconnect = p1DisconnectPayload($enrolment);
    $fixture->crashBeforeExecution = 'T4';
    $pending = $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken));
    $pending->assertAccepted();
    $this->assertBuiltForCloudMetadataEndpoint($pending, 'POST /bfc/managed/enrolment/disconnect');

    $fixture->crashBeforeExecution = null;
    $completed = $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken));
    $completed->assertOk();
    $this->assertBuiltForCloudMetadataEndpoint($completed, 'POST /bfc/managed/enrolment/disconnect');
});

it('finishes disconnect cleanup on exact retry after process loss between durable acknowledgement and cleanup', function (): void {
    [$ownerToken, $enrolment] = p1PendingDisconnectFixture();
    $disconnect = p1DisconnectPayload($enrolment);

    $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken))
        ->assertOk()
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3);

    // Fault seam: rewind to the durable state process loss leaves in
    // the window after the local transition reached Acknowledged but
    // before endpoint cleanup ran — ledger row uncommitted, the five
    // facts and the persisted secret still in place on the (already
    // standalone, generation-advanced) authority row.
    DB::table('bfc_managed_enrolment_requests')->where('id', $disconnect['disconnect_id'])->update([
        'committed_response' => null,
        'committed_at' => null,
    ]);
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'issuer' => $enrolment['issuer'],
        'connection_id' => $enrolment['connection_id'],
        'organization_id' => $enrolment['organization_id'],
        'installation_id' => $enrolment['installation_id'],
        'authority_base_url' => $enrolment['authority_base_url'],
        'updated_at' => now(),
    ]);
    app(ManagedClientSecretStore::class)->install('stranded-custody-secret');
    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(3)
        ->and(ManagedTransition::query()->count())->toBe(1)
        ->and(ManagedTransition::query()->value('status'))->toBe(ManagedTransitionStatus::Acknowledged);

    $recovered = $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken));

    $recovered->assertOk()
        ->assertJsonPath('disconnect_id', $disconnect['disconnect_id'])
        ->assertJsonPath('status', 'completed')
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3)
        ->assertJsonStructure(['disconnect_id', 'status', 'mode', 'generation', 'disconnected_at']);
    expect(p1AuthorityRow())->toMatchArray([
        'issuer' => null,
        'connection_id' => null,
        'organization_id' => null,
        'installation_id' => null,
        'authority_base_url' => null,
    ])
        ->and(DB::table('bfc_managed_client_secrets')->count())->toBe(0)
        ->and(json_decode((string) DB::table('bfc_managed_enrolment_requests')->where('id', $disconnect['disconnect_id'])->value('committed_response'), true))
        ->toBe($recovered->json());

    // The next exact retry replays the committed response byte-for-byte.
    $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken))
        ->assertOk()
        ->assertExactJson($recovered->json());
});

it('refuses transition creation when the recorded binding expectation disagrees with locked authority', function (): void {
    [, $enrolment, $owner] = p1PendingDisconnectFixture();

    expect(fn (): object => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Exit, [
        'issuer' => 'https://later-issuer.example.test',
        'connection_id' => $enrolment['connection_id'],
        'installation_id' => $enrolment['installation_id'],
        'generation' => 2,
    ]))->toThrow(ManagedAuthRefused::class)
        ->and(ManagedTransition::query()->count())->toBe(0);
});

it('answers durable pending state for a first-leg authority failure and resumes the exact transition on retry', function (): void {
    [$ownerToken, $enrolment, , $fixture] = p1PendingDisconnectFixture();
    $disconnect = p1DisconnectPayload($enrolment);

    // The authority executed T1 but the outcome was lost — exactly the
    // transport/refused-response shape the client wraps with
    // recordsFailedAttempt. The request's transition row is durable.
    $fixture->crashAfterExecution = 'T1';

    $pending = $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken));

    $pending->assertAccepted()
        ->assertJsonPath('disconnect_id', $disconnect['disconnect_id'])
        ->assertJsonPath('status', 'pending');
    $transitionId = (string) $pending->json('transition_id');
    expect($transitionId)->not->toBeEmpty()
        ->and(ManagedTransition::query()->whereKey($transitionId)->value('status'))->toBe(ManagedTransitionStatus::Preparing)
        // The ledger links EXACTLY the row this request created — never
        // an installation-wide "whatever is active" selection.
        ->and(ManagedTransition::query()->count())->toBe(1)
        ->and((array) DB::table('bfc_managed_enrolment_requests')->where('id', $disconnect['disconnect_id'])->sole())->toMatchArray([
            'committed_response' => null,
            'managed_transition_id' => $transitionId,
        ]);

    // The exact UUID retry resumes the linked Preparing row through
    // recover() and completes the disconnect.
    $fixture->crashAfterExecution = null;

    $this->postJson('/bfc/managed/enrolment/disconnect', $disconnect, p1OwnerHeaders($ownerToken))
        ->assertOk()
        ->assertJsonPath('disconnect_id', $disconnect['disconnect_id'])
        ->assertJsonPath('status', 'completed')
        ->assertJsonPath('mode', 'standalone')
        ->assertJsonPath('generation', 3);
    expect(ManagedTransition::query()->whereKey($transitionId)->value('status'))->toBe(ManagedTransitionStatus::Acknowledged);

    // The security control the wedge lost: after recovery the
    // installation can enrol and rotate its managed client secret
    // again — one authority blip no longer freezes custody.
    User::query()->delete();
    $reenrolment = p1EnrollmentPayload([
        'expected_generation' => 3,
        'managed_client_secret' => 'post-recovery-enrolment-secret',
    ]);
    p1Enroll($ownerToken, $reenrolment)->assertCreated()->assertJsonPath('generation', 4);

    $this->postJson(
        '/bfc/managed/enrolment/client-secret',
        p1RotationPayload($reenrolment, ['expected_generation' => 4]),
        p1OwnerHeaders($ownerToken),
    )->assertOk()
        ->assertJsonPath('generation', 4)
        ->assertJsonPath('client_secret_generation', 2);
});

it('carries the bounded reason when disconnect refuses because another transition is active', function (): void {
    [$ownerToken, $enrolment] = p1PendingDisconnectFixture();
    p1ActiveTransition();
    $before = p1AuthorityRow();

    $this->postJson('/bfc/managed/enrolment/disconnect', p1DisconnectPayload($enrolment), p1OwnerHeaders($ownerToken))
        ->assertStatus(409)
        ->assertJsonPath('error', 'transition_in_progress')
        ->assertJsonPath('reason', 'transition_in_progress');

    expect(p1AuthorityRow())->toBe($before);
});

it('carries the bounded reason when disconnect refuses on a standalone installation', function (): void {
    $ownerToken = p1ClaimOwner();
    $owner = User::query()->create(['name' => 'Standalone Owner', 'email' => 'standalone-owner@example.test']);
    $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();

    $this->postJson('/bfc/managed/enrolment/disconnect', p1DisconnectPayload(p1EnrollmentPayload()), p1OwnerHeaders($ownerToken))
        ->assertStatus(409)
        ->assertJsonPath('error', 'not_managed')
        ->assertJsonPath('reason', 'not_managed');
});
