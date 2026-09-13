<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);
    Route::middleware('auth:bfc')->get('/member-credential-probe', static fn (): array => ['authenticated' => true]);
});

function installationMember(UserRole|string $role, ?string $email = null): User
{
    /** @var User $user */
    $user = User::query()->create([
        'name' => 'Credential member',
        'email' => $email ?? uniqid('credential-member-', true).'@example.test',
        'password' => bcrypt('member-password'),
    ]);
    $user->forceFill([
        'role' => $role instanceof UserRole ? $role->value : $role,
        'status' => 'active',
        'email_verified_at' => now(),
    ])->save();

    return $user;
}

/** @return array{credential: Credential, secret: string} */
function installationCredential(string $name = 'deployment'): array
{
    $secret = 'installation-secret-'.bin2hex(random_bytes(12));
    /** @var Credential $credential */
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'installation-under-test',
        'name' => $name,
        'status' => CredentialStatus::Active,
        'secret_hash' => hash('sha256', $secret),
    ]);

    return compact('credential', 'secret');
}

function assertInstallationAuthentication(string $secret, int $status = 200): void
{
    test()->getJson('/member-credential-probe', [
        'Authorization' => 'Bearer '.$secret,
    ])->assertStatus($status);
}

it('lets every recognized role perform each installation credential verb with a persisted effect and authentication proof', function (
    UserRole $role,
    string $verb,
): void {
    $member = installationMember($role);
    $seeded = installationCredential($role->value.'-'.$verb);
    $this->actingAsVersioned($member);

    if ($verb === 'list') {
        $response = $this->getJson('/bfc/installation/credentials')->assertOk();
        expect($response->json('credentials.*.id'))->toContain($seeded['credential']->id)
            ->and($seeded['credential']->refresh()->revoked_at)->toBeNull();
        assertInstallationAuthentication($seeded['secret']);

        return;
    }

    if ($verb === 'issue') {
        $response = $this->postJson('/bfc/installation/credentials', [
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'matrix-'.$role->value,
            'name' => $role->value.'-issued',
            'user_id' => (string) $member->getKey(),
        ])->assertCreated();
        $issued = Credential::query()->findOrFail($response->json('credential.id'));
        $secret = (string) $response->json('delivery.secret');

        expect($issued->user_id)->toBeNull()
            ->and($issued->secret_hash)->toBe(hash('sha256', $secret));
        assertInstallationAuthentication($secret);

        return;
    }

    if ($verb === 'rotate') {
        $response = $this->postJson('/bfc/installation/credentials/'.$seeded['credential']->id.'/rotate')
            ->assertCreated();
        $replacement = Credential::query()->findOrFail($response->json('credential.id'));
        $secret = (string) $response->json('delivery.secret');

        expect($seeded['credential']->refresh()->rotated_at)->not->toBeNull()
            ->and($replacement->user_id)->toBeNull()
            ->and($replacement->secret_hash)->toBe(hash('sha256', $secret));
        assertInstallationAuthentication($secret);

        return;
    }

    $this->deleteJson('/bfc/installation/credentials/'.$seeded['credential']->id)->assertNoContent();
    expect($seeded['credential']->refresh()->revoked_at)->not->toBeNull();
    assertInstallationAuthentication($seeded['secret'], 401);
})->with(function (): array {
    $cases = [];
    foreach (UserRole::cases() as $role) {
        foreach (['list', 'issue', 'rotate', 'revoke'] as $verb) {
            $cases[$role->value.' '.$verb] = [$role, $verb];
        }
    }

    return $cases;
});

it('lets one Member manage a credential another Member issued without using issuer attribution as scope', function (): void {
    $issuer = installationMember(UserRole::Member, 'issuer@example.test');
    $manager = installationMember(UserRole::Member, 'manager@example.test');

    $issuedResponse = $this->actingAsVersioned($issuer, 'web')->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Application->value,
        'subject_ref' => 'cross-member-app',
        'name' => 'cross-member',
    ])->assertCreated();
    $issued = Credential::query()->findOrFail($issuedResponse->json('credential.id'));
    $issuedSecret = (string) $issuedResponse->json('delivery.secret');
    expect($issued->user_id)->toBeNull();
    assertInstallationAuthentication($issuedSecret);

    $listing = $this->actingAsVersioned($manager, 'web')->getJson('/bfc/installation/credentials')->assertOk();
    expect($listing->json('credentials.*.id'))->toContain($issued->id)
        ->and($issued->refresh()->revoked_at)->toBeNull();
    assertInstallationAuthentication($issuedSecret);

    $rotatedResponse = $this->actingAsVersioned($manager, 'web')
        ->postJson('/bfc/installation/credentials/'.$issued->id.'/rotate')
        ->assertCreated();
    $replacement = Credential::query()->findOrFail($rotatedResponse->json('credential.id'));
    $replacementSecret = (string) $rotatedResponse->json('delivery.secret');
    expect($replacement->user_id)->toBeNull()
        ->and($issued->refresh()->rotated_at)->not->toBeNull();
    assertInstallationAuthentication($replacementSecret);

    $this->actingAsVersioned($manager, 'web')
        ->deleteJson('/bfc/installation/credentials/'.$replacement->id)
        ->assertNoContent();
    expect($replacement->refresh()->revoked_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $replacement->id)
            ->where('event', LifecycleEventType::Revoked)
            ->value('actor_ref'))->toBe((string) $manager->getKey());
    assertInstallationAuthentication($replacementSecret, 401);
});

it('keeps installation credentials inaccessible through the personal ownership surface', function (): void {
    $member = installationMember(UserRole::Member);
    $personalSecret = 'personal-secret-'.bin2hex(random_bytes(12));
    $personal = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$member->getKey(),
        'user_id' => (string) $member->getKey(),
        'secret_hash' => hash('sha256', $personalSecret),
        'status' => CredentialStatus::Active,
    ]);
    $installation = installationCredential();

    $listing = $this->actingAsVersioned($member)->getJson('/bfc/installation/credentials')->assertOk();
    expect($listing->json('credentials.*.id'))->toContain($installation['credential']->id)
        ->not->toContain($personal->id);

    $this->postJson('/bfc/installation/credentials/'.$personal->id.'/rotate')->assertNotFound();
    $this->deleteJson('/bfc/installation/credentials/'.$personal->id)->assertNotFound();
    expect($personal->refresh()->rotated_at)->toBeNull()
        ->and($personal->revoked_at)->toBeNull();
    assertInstallationAuthentication($personalSecret);
});

it('denies an unknown stored role fail closed for every verb without changing rows or authentication', function (string $verb): void {
    $unknown = installationMember('future-role');
    $seeded = installationCredential('unknown-role-'.$verb);
    $before = Credential::query()->count();

    $request = match ($verb) {
        'list' => fn () => $this->actingAsVersioned($unknown)->getJson('/bfc/installation/credentials'),
        'issue' => fn () => $this->actingAsVersioned($unknown)->postJson('/bfc/installation/credentials', [
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'unknown-role',
        ]),
        'rotate' => fn () => $this->actingAsVersioned($unknown)->postJson('/bfc/installation/credentials/'.$seeded['credential']->id.'/rotate'),
        'revoke' => fn () => $this->actingAsVersioned($unknown)->deleteJson('/bfc/installation/credentials/'.$seeded['credential']->id),
    };

    $request()->assertForbidden();
    expect(Credential::query()->count())->toBe($before)
        ->and($seeded['credential']->refresh()->rotated_at)->toBeNull()
        ->and($seeded['credential']->revoked_at)->toBeNull();
    assertInstallationAuthentication($seeded['secret']);
})->with(['list', 'issue', 'rotate', 'revoke']);

it('keeps a Member-issued installation credential alive after creator removal and full account offboarding', function (): void {
    $creator = installationMember(UserRole::Member);
    $response = $this->actingAsVersioned($creator)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'creator-removal',
        'name' => 'survivor',
    ])->assertCreated();
    $survivor = Credential::query()->findOrFail($response->json('credential.id'));
    $secret = (string) $response->json('delivery.secret');
    assertInstallationAuthentication($secret);

    $creator->forceFill(['status' => 'inactive'])->save();
    expect($survivor->refresh()->revoked_at)->toBeNull();
    assertInstallationAuthentication($secret);

    $creator->forceFill(['status' => 'active'])->save();
    $bound = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$creator->getKey(),
        'user_id' => (string) $creator->getKey(),
        'secret_hash' => hash('sha256', 'creator-bound-secret'),
        'status' => CredentialStatus::Active,
    ]);
    app(OffboardSubject::class)(new OffboardOptions(
        subjectType: SubjectType::UserPrincipal,
        subjectRef: 'user:'.$creator->getKey(),
    ));

    expect($bound->refresh()->revoked_at)->not->toBeNull()
        ->and(OffboardedSubject::userIsOffboarded((string) $creator->getKey()))->toBeTrue()
        ->and($survivor->refresh()->revoked_at)->toBeNull()
        ->and(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret)?->id)->toBe($survivor->id);
    assertInstallationAuthentication($secret);
});
