<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesRotationOverrides;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotationOverride;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        'built-for-cloud.credentials.app_purposes' => [
            'test.deploy' => CredentialPurpose::SystemDeployment->value,
            'test.consume' => CredentialPurpose::Consumption->value,
            'test.mcp' => CredentialPurpose::Mcp->value,
        ],
        'built-for-cloud.ui.credential_purposes' => ['test.deploy', 'test.consume', 'test.mcp'],
    ]);
    Route::middleware('auth:bfc')->get('/member-credential-probe', static fn (): array => ['authenticated' => true]);
    Route::middleware('bfc.mcp')->post('/member-mcp-probe', static fn (): array => ['authenticated' => true]);
    Route::middleware('bfc.ability:custom:deploy')->get('/member-custom-ability-probe', static fn (): array => ['authorized' => true]);
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
        'purpose' => CredentialPurpose::SystemDeployment,
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

it('pins both live lifecycle passes to one credential subject', function (): void {
    $harness = (string) file_get_contents(__DIR__.'/Live/run-member-credential-harness.sh');

    expect($harness)->toContain('for pass in 1 2', "--data-urlencode 'subject_ref=live-member'")
        ->not->toContain('subject_ref=live-member-${pass}');
});

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
            'purpose' => CredentialPurpose::SystemDeployment->value,
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

it('lets a Member mint each installation app purpose through the JSON API', function (
    CredentialPurpose $purpose,
    CredentialKind $kind,
): void {
    $member = installationMember(UserRole::Member);
    $response = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'member-'.$purpose->value.'-'.$kind->value,
        'kind' => $kind->value,
        'purpose' => $purpose->value,
        'name' => 'member-'.$purpose->value.'-'.$kind->value,
    ])->assertCreated();
    $credential = Credential::query()->findOrFail($response->json('credential.id'));

    expect($credential->purpose)->toBe($purpose)
        ->and($credential->kind)->toBe($kind)
        ->and($credential->subject_type)->toBe(SubjectType::Installation)
        ->and($credential->user_id)->toBeNull();
})->with([
    'consumption bearer' => [CredentialPurpose::Consumption, CredentialKind::Bearer],
    'consumption basic' => [CredentialPurpose::Consumption, CredentialKind::Basic],
    'mcp bearer' => [CredentialPurpose::Mcp, CredentialKind::Bearer],
    'mcp basic' => [CredentialPurpose::Mcp, CredentialKind::Basic],
]);

it('restricts JSON installation issuance to purposes reachable from displayed app purposes', function (): void {
    config(['built-for-cloud.ui.credential_purposes' => ['test.consume']]);
    $member = installationMember(UserRole::Member);

    foreach ([CredentialPurpose::Mcp, CredentialPurpose::SystemDeployment] as $purpose) {
        $before = [Credential::query()->count(), CredentialAuditEvent::query()->count()];
        $response = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'refused-'.$purpose->value,
            'purpose' => $purpose->value,
        ])->assertForbidden();

        expect($response->json('delivery'))->toBeNull()
            ->and([Credential::query()->count(), CredentialAuditEvent::query()->count()])->toBe($before);
    }

    $response = $this->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'allowed-consumption',
        'purpose' => CredentialPurpose::Consumption->value,
    ])->assertCreated();

    expect($response->json('delivery.secret'))->toBeString()
        ->and(Credential::query()->findOrFail($response->json('credential.id'))->purpose)
        ->toBe(CredentialPurpose::Consumption);
});

it('matches the empty HTML purpose list without defaulting an omitted JSON purpose', function (): void {
    config(['built-for-cloud.ui.credential_purposes' => []]);
    $member = installationMember(UserRole::Member);
    $before = [Credential::query()->count(), CredentialAuditEvent::query()->count()];

    expect(app(UiCredentialPurposes::class)->displayed())->toBe([]);

    $supplied = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'no-declaration-supplied',
        'purpose' => CredentialPurpose::Consumption->value,
    ])->assertForbidden();
    $omitted = $this->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'no-declaration-omitted',
    ])->assertUnprocessable();

    expect($supplied->json('delivery'))->toBeNull()
        ->and($omitted->json('message'))->toContain('purpose is required')
        ->and($omitted->json('delivery'))->toBeNull()
        ->and([Credential::query()->count(), CredentialAuditEvent::query()->count()])->toBe($before);
});

it('applies the bearer-only host policy to JSON installation issue and rotation', function (): void {
    config(['built-for-cloud.credentials.declaration' => SelfServicePolicyDeclaration::class]);
    SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer];
    SelfServicePolicyDeclaration::$abilities = [];
    $member = installationMember(UserRole::Member);
    $beforeIssue = [
        Credential::query()->count(),
        CredentialAuditEvent::query()->count(),
    ];
    $issue = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Application->value,
        'subject_ref' => 'json-forged-basic-issue',
        'kind' => CredentialKind::Basic->value,
        'purpose' => CredentialPurpose::SystemDeployment->value,
    ])->assertForbidden();

    expect($issue->json('delivery'))->toBeNull()
        ->and([Credential::query()->count(), CredentialAuditEvent::query()->count()])->toBe($beforeIssue);

    $source = Credential::query()->create([
        'kind' => CredentialKind::Basic,
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'json-forged-basic-rotation',
        'status' => CredentialStatus::Active,
        'secret_hash' => hash('sha256', 'json-forged-basic-rotation-secret'),
    ]);
    $beforeRotation = [
        Credential::query()->count(),
        CredentialAuditEvent::query()->count(),
    ];
    $rotation = $this->postJson('/bfc/installation/credentials/'.$source->id.'/rotate')
        ->assertForbidden();

    expect($rotation->json('delivery'))->toBeNull()
        ->and([Credential::query()->count(), CredentialAuditEvent::query()->count()])->toBe($beforeRotation)
        ->and($source->refresh()->rotated_at)->toBeNull();
});

it('refuses an installation MCP credential at the consumption gate', function (): void {
    $secret = 'installation-mcp-wrong-consumption-purpose-'.bin2hex(random_bytes(12));
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'mcp-not-consumption',
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);

    $this->getJson('/member-credential-probe', [
        'Authorization' => 'Bearer '.$secret,
    ])->assertUnauthorized();

    expect($credential->refresh()->last_used_at)->toBeNull();
});

it('refuses every operator-vocabulary ability before a Member can mint a credential or receive its secret', function (string $ability): void {
    $member = installationMember(UserRole::Member);
    $before = Credential::query()->count();

    $response = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Application->value,
        'subject_ref' => 'member-operator-ability',
        'purpose' => CredentialPurpose::SystemDeployment->value,
        'abilities' => [$ability],
    ])->assertForbidden();

    expect($response->json('message'))->toContain($ability)
        ->and($response->json('delivery.secret'))->toBeNull()
        ->and(Credential::query()->count())->toBe($before);
})->with(function (): array {
    $abilities = [];

    foreach (OperatorAbility::cases() as $ability) {
        $abilities[$ability->value] = [$ability->value];
    }

    return $abilities;
});

it('keeps operator-abilitied application rows outside every Member management verb', function (): void {
    $member = installationMember(UserRole::Member);
    $secret = 'operator-application-secret-'.bin2hex(random_bytes(12));
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'operator-managed-application',
        'abilities' => [OperatorAbility::McpAdmin->value],
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);
    $before = Credential::query()->count();

    $listing = $this->actingAsVersioned($member)->getJson('/bfc/installation/credentials')->assertOk();
    expect($listing->json('credentials.*.id'))->not->toContain($credential->id);

    $rotation = $this->postJson('/bfc/installation/credentials/'.$credential->id.'/rotate')->assertNotFound();
    expect($rotation->json('delivery.secret'))->toBeNull()
        ->and(Credential::query()->count())->toBe($before)
        ->and($credential->refresh()->rotated_at)->toBeNull()
        ->and($credential->revoked_at)->toBeNull();

    $this->deleteJson('/bfc/installation/credentials/'.$credential->id)->assertNotFound();
    expect($credential->refresh()->rotated_at)->toBeNull()
        ->and($credential->revoked_at)->toBeNull();
    assertInstallationAuthentication($secret);
});

it('refuses an authorized Member rotation override whose effective abilities enter operator vocabulary', function (): void {
    app()->instance(CredentialDeclaration::class, new class implements AuthorizesRotationOverrides, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeRotationOverride(?Subject $subject, RotationOverride $override, Request $request): bool
        {
            return true;
        }
    });

    $member = installationMember(UserRole::Member);
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'member-rotation-override',
        'abilities' => null,
        'secret_hash' => hash('sha256', 'member-rotation-override-secret'),
        'status' => CredentialStatus::Active,
    ]);
    $before = Credential::query()->count();

    $response = $this->actingAsVersioned($member)->postJson(
        '/bfc/installation/credentials/'.$credential->id.'/rotate',
        [
            'override' => true,
            'abilities' => [OperatorAbility::McpAdmin->value],
        ],
    )->assertForbidden();

    expect($response->json('message'))->toContain(OperatorAbility::McpAdmin->value)
        ->and($response->json('delivery.secret'))->toBeNull()
        ->and(Credential::query()->count())->toBe($before)
        ->and($credential->refresh()->rotated_at)->toBeNull()
        ->and($credential->revoked_at)->toBeNull();
});

it('keeps a deploy-read application row fully manageable by a Member', function (): void {
    $member = installationMember(UserRole::Member);
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'subject_ref' => 'member-deploy-read',
        'abilities' => null,
        'secret_hash' => hash('sha256', 'member-deploy-read-secret'),
        'status' => CredentialStatus::Active,
    ]);

    $listing = $this->actingAsVersioned($member)->getJson('/bfc/installation/credentials')->assertOk();
    expect($listing->json('credentials.*.id'))->toContain($credential->id);

    $rotation = $this->postJson('/bfc/installation/credentials/'.$credential->id.'/rotate')->assertCreated();
    $replacement = Credential::query()->findOrFail($rotation->json('credential.id'));
    expect($replacement->abilities)->toBeNull()
        ->and($credential->refresh()->rotated_at)->not->toBeNull();

    $this->deleteJson('/bfc/installation/credentials/'.$replacement->id)->assertNoContent();
    expect($replacement->refresh()->revoked_at)->not->toBeNull();
});

it('refuses an unknown ability on the Member mint surface without writing', function (): void {
    $member = installationMember(UserRole::Member);
    $before = Credential::query()->count();
    $response = $this->actingAsVersioned($member)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Application->value,
        'subject_ref' => 'member-custom-ability',
        'purpose' => CredentialPurpose::SystemDeployment->value,
        'abilities' => ['custom:deploy'],
    ])->assertUnprocessable();

    expect($response->json('message'))->toContain('Unknown credential ability')
        ->and(Credential::query()->count())->toBe($before);
});

it('lets one Member manage a credential another Member issued without using issuer attribution as scope', function (): void {
    $issuer = installationMember(UserRole::Member, 'issuer@example.test');
    $manager = installationMember(UserRole::Member, 'manager@example.test');

    $issuedResponse = $this->actingAsVersioned($issuer, 'web')->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Application->value,
        'subject_ref' => 'cross-member-app',
        'purpose' => CredentialPurpose::SystemDeployment->value,
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
        'purpose' => CredentialPurpose::Consumption,
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

it('keeps null-user operator and external-consumer credentials outside the installation surface', function (SubjectType $subjectType): void {
    $member = installationMember(UserRole::Member);
    $secret = $subjectType->value.'-secret-'.bin2hex(random_bytes(12));
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => $subjectType === SubjectType::Operator
            ? CredentialPurpose::OperatorManagement
            : CredentialPurpose::Consumption,
        'subject_type' => $subjectType,
        'subject_ref' => $subjectType->value.'-under-test',
        'abilities' => $subjectType === SubjectType::Operator ? [OperatorAbility::Admin->value] : null,
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);

    $listing = $this->actingAsVersioned($member)->getJson('/bfc/installation/credentials')->assertOk();
    expect($listing->json('credentials.*.id'))->not->toContain($credential->id);

    $this->postJson('/bfc/installation/credentials/'.$credential->id.'/rotate')->assertNotFound();
    $this->deleteJson('/bfc/installation/credentials/'.$credential->id)->assertNotFound();

    expect($credential->refresh()->rotated_at)->toBeNull()
        ->and($credential->revoked_at)->toBeNull();
    assertInstallationAuthentication(
        $secret,
        $subjectType === SubjectType::Operator ? 401 : 200,
    );
})->with([
    'operator' => SubjectType::Operator,
    'external consumer' => SubjectType::ExternalConsumer,
]);

it('makes a personal HMAC id indistinguishable from an unknown id during APP_KEY cutover', function (): void {
    $member = installationMember(UserRole::Member);
    $oldKey = (string) config('app.key');
    $encrypted = app(HmacKeyring::class)->encrypt('personal-hmac-secret');
    $personal = new Credential;
    $personal->forceFill([
        'kind' => CredentialKind::Hmac,
        'purpose' => CredentialPurpose::Signing,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$member->getKey(),
        'user_id' => (string) $member->getKey(),
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'status' => CredentialStatus::Active,
    ])->save();
    config()->set('app.previous_keys', [$oldKey]);
    config()->set('app.key', 'base64:'.base64_encode(random_bytes(32)));

    expect(app(HmacKeyring::class)->cutoverInProgress())->toBeTrue();
    $personalResponse = $this->actingAsVersioned($member)
        ->postJson('/bfc/installation/credentials/'.$personal->id.'/rotate');
    $unknownResponse = $this->postJson('/bfc/installation/credentials/'.Str::uuid().'/rotate');

    expect($personalResponse->status())->toBe(404)
        ->and($unknownResponse->status())->toBe($personalResponse->status())
        ->and($unknownResponse->getContent())->toBe($personalResponse->getContent())
        ->and($personal->refresh()->rotated_at)->toBeNull();
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
            'purpose' => CredentialPurpose::SystemDeployment->value,
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

it('keeps a Member-issued installation app credential alive after creator removal and full account offboarding', function (
    CredentialPurpose $purpose,
): void {
    $creator = installationMember(UserRole::Member);
    $response = $this->actingAsVersioned($creator)->postJson('/bfc/installation/credentials', [
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'creator-removal',
        'purpose' => $purpose->value,
        'name' => 'survivor',
    ])->assertCreated();
    $survivor = Credential::query()->findOrFail($response->json('credential.id'));
    $secret = (string) $response->json('delivery.secret');
    $authenticate = function () use ($purpose, $secret): void {
        $purpose === CredentialPurpose::Mcp
            ? $this->postJson('/member-mcp-probe', [], ['Authorization' => 'Bearer '.$secret])->assertOk()
            : assertInstallationAuthentication($secret);
    };
    $authenticate();

    $creator->forceFill(['status' => 'inactive'])->save();
    expect($survivor->refresh()->revoked_at)->toBeNull();
    $authenticate();

    $creator->forceFill(['status' => 'active'])->save();
    $bound = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
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
    $authenticate();
})->with([
    'consumption' => CredentialPurpose::Consumption,
    'mcp' => CredentialPurpose::Mcp,
]);
