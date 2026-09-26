<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiPersonalCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;

final class PersonalCredentialUiTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        UiPersonalCredentialDeclaration::$kinds = CredentialKind::cases();
        UiPersonalCredentialDeclaration::$abilities = [OperatorAbility::McpRead->value];
        UiPersonalCredentialDeclaration::$deniedVerbs = [];
        UiPersonalCredentialDeclaration::$resolvesSubject = true;
        UiPersonalCredentialDeclaration::$subjectRef = null;

        config([
            'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
            'built-for-cloud.credentials.declaration' => UiPersonalCredentialDeclaration::class,
            'built-for-cloud.credentials.app_purposes' => [
                'test.consume' => CredentialPurpose::Consumption->value,
                'test.mcp' => CredentialPurpose::Mcp->value,
                'test.sign' => CredentialPurpose::Signing->value,
                'test.enroll' => CredentialPurpose::Enrollment->value,
            ],
            'built-for-cloud.ui.credential_purposes' => [
                'test.consume', 'test.mcp', 'test.sign', 'test.enroll',
            ],
            'built-for-cloud.ui.personal_credentials' => true,
            'built-for-cloud.manifest' => [
                'name' => 'Test-created personal credential application',
                'slug' => 'test-created-personal-credential-application',
                'description' => 'Test-created personal credential description',
                'icon' => 'https://assets.example.test/personal-credential.svg',
                'product_url' => 'https://scalpels.app/products/test-created-personal-credential-application',
            ],
        ]);
    }

    /** @return iterable<string, array{UserRole, string, CredentialPurpose, CredentialKind}> */
    public static function rolePurposeKindProvider(): iterable
    {
        $pairs = [
            ['test.consume', CredentialPurpose::Consumption, CredentialKind::Bearer],
            ['test.consume', CredentialPurpose::Consumption, CredentialKind::Basic],
            ['test.mcp', CredentialPurpose::Mcp, CredentialKind::Bearer],
            ['test.mcp', CredentialPurpose::Mcp, CredentialKind::Basic],
            ['test.sign', CredentialPurpose::Signing, CredentialKind::Hmac],
            ['test.enroll', CredentialPurpose::Enrollment, CredentialKind::Asymmetric],
        ];

        foreach (UserRole::cases() as $role) {
            foreach ($pairs as [$appPurpose, $purpose, $kind]) {
                yield $role->value.'-'.$appPurpose.'-'.$kind->value => [$role, $appPurpose, $purpose, $kind];
            }
        }
    }

    #[DataProvider('rolePurposeKindProvider')]
    public function test_every_role_and_admitted_pair_lists_issues_rotates_revokes_and_authenticates(
        UserRole $role,
        string $appPurpose,
        CredentialPurpose $purpose,
        CredentialKind $kind,
    ): void {
        $user = $this->user($role);
        $victim = $this->user(UserRole::Member);
        $name = 'test-created-'.$role->value.'-'.$appPurpose.'-'.$kind->value;

        $page = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'));
        $page->assertOk()
            ->assertSeeHtml('data-testid="personal-credentials"')
            ->assertSee($appPurpose)
            ->assertSee($kind->value);
        $this->assertSame(1, substr_count((string) $page->getContent(), '<main>'));

        $issue = $this->post(route('bfc.ui.personal-credentials.store'), [
            SubmissionNonce::FIELD => $this->submissionNonce($page, route('bfc.ui.personal-credentials.store')),
            'app_purpose' => $appPurpose,
            'kind' => $kind->value,
            'name' => $name,
            'code_ttl_seconds' => $kind === CredentialKind::Asymmetric ? 120 : null,
            'purpose' => CredentialPurpose::SigningRoot->value,
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'ui-user:'.$victim->getKey(),
            'user_id' => (string) $victim->getKey(),
            'abilities' => [OperatorAbility::Admin->value],
            'root' => CredentialPurpose::SIGNING_ROOT_SUBJECT_REF,
        ])->assertCreated()
            ->assertSeeHtml('data-testid="personal-credentials-delivery"');
        $issueEffects = $this->effects();

        $issued = Credential::query()->where('name', $name)->sole();
        $secret = $this->deliverySecret($issue, $kind);
        $this->assertSame(1, substr_count((string) $issue->getContent(), $secret));
        $this->assertSame($kind, $issued->kind);
        $this->assertSame($purpose, $issued->purpose);
        $this->assertSame(SubjectType::UserPrincipal, $issued->subject_type);
        $this->assertSame('ui-user:'.$user->getKey(), $issued->subject_ref);
        $this->assertSame((string) $user->getKey(), (string) $issued->user_id);
        $this->assertSame([OperatorAbility::McpRead->value], $issued->abilities);

        $revisit = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'));
        $revisit->assertOk()->assertSee($name)->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertStringNotContainsString($secret, (string) $revisit->getContent());
        $this->assertSame($issueEffects, $this->effects());

        if ($kind === CredentialKind::Hmac) {
            $this->activateHmac($issued, $issue);
            $this->assertHmacAuthenticates($user, $issued->id, $secret);
        } elseif ($kind !== CredentialKind::Asymmetric) {
            $this->assertSecretAuthenticates($issued, $secret, $purpose);
        } else {
            $this->assertSame(CredentialStatus::Pending, $issued->status);
            $this->assertNull($issued->public_key);
            $this->assertStringContainsString('pending and keyless', (string) $issue->getContent());
            $this->assertStringNotContainsString('completed public-key', (string) $issue->getContent());
        }

        $rotationSource = $kind === CredentialKind::Asymmetric
            ? $this->activeAsymmetric($user, $name.'-active')
            : $issued;
        $rotationPage = $kind === CredentialKind::Asymmetric
            ? $this->get(route('bfc.ui.personal-credentials.index'))->assertOk()
            : $issue;
        $rotate = $this->post(
            route('bfc.ui.personal-credentials.rotate', $rotationSource->id),
            [
                SubmissionNonce::FIELD => $this->submissionNonce(
                    $rotationPage,
                    route('bfc.ui.personal-credentials.rotate', $rotationSource->id),
                ),
                ...($kind === CredentialKind::Asymmetric
                    ? ['code_ttl_seconds' => 120, 'abilities' => [OperatorAbility::Admin->value], 'emergency' => true]
                    : ['abilities' => [OperatorAbility::Admin->value], 'emergency' => true]),
            ],
        )->assertCreated()
            ->assertSeeHtml('data-testid="personal-credentials-delivery"');
        $rotationEffects = $this->effects();

        $rotationSecret = $this->deliverySecret($rotate, $kind);
        $replacement = Credential::query()->where('name', $rotationSource->name)
            ->whereKeyNot($rotationSource->id)
            ->sole();
        $this->assertSame($rotationSource->purpose, $replacement->purpose);
        $this->assertSame($rotationSource->subject_type, $replacement->subject_type);
        $this->assertSame($rotationSource->subject_ref, $replacement->subject_ref);
        $this->assertSame((string) $rotationSource->user_id, (string) $replacement->user_id);
        $this->assertSame($rotationSource->abilities, $replacement->abilities);
        $this->assertNotNull($rotationSource->refresh()->rotated_at);
        $this->assertSame(1, substr_count((string) $rotate->getContent(), $rotationSecret));
        $rotationRevisit = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'));
        $rotationRevisit->assertOk()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertStringNotContainsString($rotationSecret, (string) $rotationRevisit->getContent());
        $this->assertSame($rotationEffects, $this->effects());

        if ($kind === CredentialKind::Hmac) {
            $this->assertHmacAuthenticates($user, $issued->id, $secret);
            $this->activateHmac($replacement, $rotate);
            $this->assertHmacAuthenticates($user, $replacement->id, $rotationSecret);
        } elseif ($kind !== CredentialKind::Asymmetric) {
            $this->assertSecretAuthenticates($rotationSource, $secret, $purpose);
            $this->assertSecretAuthenticates($replacement, $rotationSecret, $purpose);
        } else {
            $this->assertSame(CredentialStatus::Pending, $replacement->status);
            $this->assertNull($replacement->public_key);
        }

        $this->travelTo(now()->addSeconds(3601));

        if ($kind === CredentialKind::Hmac) {
            $this->assertHmacDoesNotAuthenticate($user, $issued->id, $secret);
            $this->assertHmacAuthenticates($user, $replacement->id, $rotationSecret);
        } elseif ($kind !== CredentialKind::Asymmetric) {
            $this->assertSecretDoesNotAuthenticate($rotationSource, $secret, $purpose);
            $this->assertSecretAuthenticates($replacement, $rotationSecret, $purpose);
        }

        $revoke = $kind === CredentialKind::Asymmetric ? $issued : $replacement;
        $this->actingAsVersioned($user, 'web')
            ->delete(route('bfc.ui.personal-credentials.destroy', $revoke->id))
            ->assertRedirect(route('bfc.ui.personal-credentials.index'))
            ->assertStatus(303);
        $this->assertNotNull($revoke->refresh()->revoked_at);

        if ($kind === CredentialKind::Hmac) {
            $this->assertHmacDoesNotAuthenticate($user, $replacement->id, $rotationSecret);
        } elseif ($kind !== CredentialKind::Asymmetric) {
            $this->assertSecretDoesNotAuthenticate($replacement, $rotationSecret, $purpose);
        }
    }

    public function test_issue_and_rotate_deliver_immediately_and_replay_refuses_without_effects(): void
    {
        $user = $this->user(UserRole::Member);
        $this->actingAsVersioned($user, 'web');

        $page = $this->get(route('bfc.ui.personal-credentials.index'))->assertOk();
        $issuePayload = [
            SubmissionNonce::FIELD => $this->submissionNonce($page, route('bfc.ui.personal-credentials.store')),
            'app_purpose' => 'test.consume',
            'kind' => CredentialKind::Bearer->value,
            'name' => 'test-created-refresh-proof',
        ];
        $issueDelivery = $this->post(route('bfc.ui.personal-credentials.store'), $issuePayload)
            ->assertCreated()
            ->assertSeeHtml('data-testid="personal-credentials-delivery"')
            ->assertHeader('Cache-Control', 'no-store, private');

        $afterIssue = $this->effects();
        $issueSecret = $this->deliverySecret($issueDelivery, CredentialKind::Bearer);
        $this->assertSame($afterIssue, $this->effects());

        $this->post(route('bfc.ui.personal-credentials.store'), $issuePayload)
            ->assertStatus(409)
            ->assertDontSeeHtml('data-testid="personal-credentials-delivery"')
            ->assertDontSee($issueSecret);
        $this->assertSame($afterIssue, $this->effects());

        $issued = Credential::query()->where('name', 'test-created-refresh-proof')->sole();
        $rotatePayload = [SubmissionNonce::FIELD => $this->submissionNonce(
            $issueDelivery,
            route('bfc.ui.personal-credentials.rotate', $issued->id),
        )];
        $rotateDelivery = $this->post(route('bfc.ui.personal-credentials.rotate', $issued->id), $rotatePayload)
            ->assertCreated()
            ->assertSeeHtml('data-testid="personal-credentials-delivery"')
            ->assertHeader('Cache-Control', 'no-store, private');

        $afterRotate = $this->effects();
        $rotationSecret = $this->deliverySecret($rotateDelivery, CredentialKind::Bearer);
        $this->assertSame($afterRotate, $this->effects());

        $this->post(route('bfc.ui.personal-credentials.rotate', $issued->id), $rotatePayload)
            ->assertStatus(409)
            ->assertDontSeeHtml('data-testid="personal-credentials-delivery"')
            ->assertDontSee($rotationSecret);
        $this->assertSame($afterRotate, $this->effects());

        $this->get(route('bfc.ui.personal-credentials.index'))
            ->assertOk()
            ->assertDontSeeHtml('data-testid="personal-credentials-delivery"')
            ->assertDontSee($issueSecret)
            ->assertDontSee($rotationSecret);
    }

    public function test_cross_user_unknown_and_invalid_submission_refusals_have_no_effect_or_delivery(): void
    {
        $actor = $this->user(UserRole::Member);
        $victim = $this->user(UserRole::Member);
        $foreign = $this->personalCredential($victim);
        $this->actingAsVersioned($actor, 'web');
        $this->get(route('bfc.ui.personal-credentials.index'))->assertOk()->assertDontSee($foreign->name);

        foreach ([
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $foreign->id)),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $foreign->id)),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', '00000000-0000-0000-0000-000000000000')),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', '00000000-0000-0000-0000-000000000000')),
        ] as $request) {
            $before = $this->effects();
            $response = $request()->assertNotFound();
            $this->assertSame($before, $this->effects());
            $response->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        }

        foreach ([
            'missing' => [],
            'malformed' => ['app_purpose' => ['test.consume'], 'kind' => 'bearer'],
            'unoffered' => ['app_purpose' => 'test.hidden', 'kind' => 'bearer'],
            'unmapped' => ['app_purpose' => 'test.unmapped', 'kind' => 'bearer'],
            'reserved root' => ['app_purpose' => 'test.root', 'kind' => 'hmac'],
        ] as $label => $payload) {
            config(['built-for-cloud.credentials.app_purposes' => [
                ...config('built-for-cloud.credentials.app_purposes'),
                'test.hidden' => CredentialPurpose::Consumption->value,
                'test.root' => CredentialPurpose::SigningRoot->value,
            ]]);
            $before = $this->effects();
            $response = $this->post(route('bfc.ui.personal-credentials.store'), $payload)->assertUnprocessable();
            $this->assertSame($before, $this->effects(), $label);
            $response->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        }

        foreach ([
            ['app_purpose' => 'test.consume', 'kind' => 'unknown-kind'],
            ['app_purpose' => 'test.sign', 'kind' => CredentialKind::Bearer->value],
        ] as $payload) {
            $before = $this->effects();
            $this->post(route('bfc.ui.personal-credentials.store'), $payload)->assertUnprocessable()
                ->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }

        UiPersonalCredentialDeclaration::$kinds = [CredentialKind::Bearer];
        $before = $this->effects();
        $this->post(route('bfc.ui.personal-credentials.store'), [
            'app_purpose' => 'test.sign',
            'kind' => CredentialKind::Hmac->value,
        ])->assertForbidden()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertSame($before, $this->effects());

        $this->allFlagsOff();
        UiPersonalCredentialDeclaration::$kinds = CredentialKind::cases();
        $this->get(route('bfc.ui.personal-credentials.index'))->assertOk()->assertDontSee($foreign->name);

        foreach ([
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $foreign->id)),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $foreign->id)),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', '00000000-0000-0000-0000-000000000000')),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', '00000000-0000-0000-0000-000000000000')),
        ] as $request) {
            $before = $this->effects();
            $request()->assertNotFound()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }

        foreach ([
            [],
            ['app_purpose' => ['test.consume'], 'kind' => 'bearer'],
            ['app_purpose' => 'test.hidden', 'kind' => 'bearer'],
            ['app_purpose' => 'test.unmapped', 'kind' => 'bearer'],
            ['app_purpose' => 'test.root', 'kind' => 'hmac'],
            ['app_purpose' => 'test.consume', 'kind' => 'unknown-kind'],
            ['app_purpose' => 'test.sign', 'kind' => CredentialKind::Bearer->value],
        ] as $payload) {
            $before = $this->effects();
            $this->post(route('bfc.ui.personal-credentials.store'), $payload)
                ->assertUnprocessable()
                ->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }
    }

    public function test_same_subject_different_user_rows_stay_outside_html_json_and_shared_mutations(): void
    {
        $actor = $this->user(UserRole::Member);
        $victim = $this->user(UserRole::Member);
        UiPersonalCredentialDeclaration::$subjectRef = 'shared-personal-subject';
        $foreign = $this->personalCredential($victim);
        $foreign->forceFill(['subject_ref' => 'shared-personal-subject'])->save();
        $this->actingAsVersioned($actor, 'web');

        $this->get(route('bfc.ui.personal-credentials.index'))
            ->assertOk()
            ->assertDontSee($foreign->id)
            ->assertDontSee($foreign->name);
        $this->getJson('/bfc/me/credentials')
            ->assertOk()
            ->assertJsonPath('credentials', [])
            ->assertDontSee($foreign->id);

        foreach ([
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $foreign->id)),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $foreign->id)),
            fn (): TestResponse => $this->deleteJson('/bfc/me/credentials/'.$foreign->id),
        ] as $request) {
            $before = $this->effects();
            $request()->assertNotFound()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }

        $request = Request::create('/bfc/me/credentials/'.$foreign->id.'/rotate', 'POST');
        $request->setUserResolver(static fn (): User => $actor);
        $before = $this->effects();
        $this->assertNull(app(PersonalCredentialSurface::class)->rotateMine($request, $foreign->id, new RotateOptions));
        $this->assertSame($before, $this->effects());
        $this->assertNull($foreign->refresh()->rotated_at);
        $this->assertNull($foreign->revoked_at);
    }

    public function test_null_subject_refuses_every_html_verb_without_effect_or_delivery(): void
    {
        $user = $this->user(UserRole::Member);
        $credential = $this->personalCredential($user);
        UiPersonalCredentialDeclaration::$resolvesSubject = false;
        $this->actingAsVersioned($user, 'web');

        foreach ([
            fn (): TestResponse => $this->get(route('bfc.ui.personal-credentials.index')),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.store'), [
                'app_purpose' => 'test.consume', 'kind' => CredentialKind::Bearer->value,
            ]),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $credential->id)),
            fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $credential->id)),
        ] as $request) {
            $before = $this->effects();
            $request()->assertForbidden()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }
    }

    public function test_submission_nonce_is_hash_only_and_bound_to_session_verb_and_target(): void
    {
        $user = $this->user(UserRole::Member);
        $other = $this->user(UserRole::Member);
        $credential = $this->personalCredential($user);
        $otherCredential = $this->personalCredential($user, [
            'name' => 'test-created-other-target',
            'secret_hash' => hash('sha256', 'test-created-other-target'),
        ]);
        $page = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'))->assertOk();
        $issueNonce = $this->submissionNonce($page, route('bfc.ui.personal-credentials.store'));
        $rotateNonce = $this->submissionNonce($page, route('bfc.ui.personal-credentials.rotate', $credential->id));

        $this->assertFalse(DB::table('bfc_submission_nonces')->where('nonce_hash', $issueNonce)->exists());
        $this->assertTrue(DB::table('bfc_submission_nonces')->where('nonce_hash', hash('sha256', $issueNonce))->exists());
        $this->assertStringNotContainsString($issueNonce, json_encode(session()->all(), JSON_THROW_ON_ERROR));

        foreach ([
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.store'), [
                'app_purpose' => 'test.consume', 'kind' => CredentialKind::Bearer->value,
            ]),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $credential->id), [
                SubmissionNonce::FIELD => $issueNonce,
            ]),
            fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $otherCredential->id), [
                SubmissionNonce::FIELD => $rotateNonce,
            ]),
        ] as $request) {
            $before = $this->effects();
            $request()->assertStatus(409)->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }

        $before = $this->effects();
        $this->actingAsVersioned($other, 'web')->post(route('bfc.ui.personal-credentials.store'), [
            SubmissionNonce::FIELD => $issueNonce,
            'app_purpose' => 'test.consume',
            'kind' => CredentialKind::Bearer->value,
        ])->assertStatus(409)->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertSame($before, $this->effects());
    }

    public function test_out_of_policy_rotation_refuses_and_in_policy_rotation_succeeds(): void
    {
        $user = $this->user(UserRole::Member);
        $outOfPolicy = $this->personalCredential($user);
        $outOfPolicy->forceFill([
            'kind' => CredentialKind::Basic,
            'abilities' => [OperatorAbility::Admin->value],
        ])->save();
        UiPersonalCredentialDeclaration::$kinds = [CredentialKind::Bearer];
        UiPersonalCredentialDeclaration::$abilities = [];
        $page = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.personal-credentials.index'))->assertOk();
        $before = $this->effects();

        $this->post(route('bfc.ui.personal-credentials.rotate', $outOfPolicy->id), [
            SubmissionNonce::FIELD => $this->submissionNonce(
                $page,
                route('bfc.ui.personal-credentials.rotate', $outOfPolicy->id),
            ),
        ])->assertForbidden()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertSame($before, $this->effects());
        $this->assertNull($outOfPolicy->refresh()->rotated_at);

        $allowed = $this->personalCredential($user, [
            'name' => 'test-created-in-policy',
            'abilities' => null,
            'secret_hash' => hash('sha256', 'test-created-in-policy'),
        ]);
        $allowedPage = $this->get(route('bfc.ui.personal-credentials.index'))->assertOk();
        $this->post(route('bfc.ui.personal-credentials.rotate', $allowed->id), [
            SubmissionNonce::FIELD => $this->submissionNonce(
                $allowedPage,
                route('bfc.ui.personal-credentials.rotate', $allowed->id),
            ),
        ])->assertCreated()->assertSeeHtml('data-testid="personal-credentials-delivery"');
        $this->assertNotNull($allowed->refresh()->rotated_at);
    }

    public function test_declaration_refusals_and_all_flags_off_direct_refusals_preserve_every_effect(): void
    {
        $user = $this->user(UserRole::Owner);
        $credential = $this->personalCredential($user);
        $this->actingAsVersioned($user, 'web');

        foreach ([CredentialVerb::Issue, CredentialVerb::Rotate, CredentialVerb::Revoke] as $verb) {
            UiPersonalCredentialDeclaration::$deniedVerbs = [$verb];
            $before = $this->effects();
            $response = match ($verb) {
                CredentialVerb::Issue => $this->post(route('bfc.ui.personal-credentials.store'), [
                    'app_purpose' => 'test.consume', 'kind' => 'bearer',
                ]),
                CredentialVerb::Rotate => $this->post(route('bfc.ui.personal-credentials.rotate', $credential->id)),
                CredentialVerb::Revoke => $this->delete(route('bfc.ui.personal-credentials.destroy', $credential->id)),
                default => throw new \LogicException('Unexpected verb.'),
            };
            $response->assertForbidden()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }

        $this->allFlagsOff();
        UiPersonalCredentialDeclaration::$deniedVerbs = [];
        $request = Request::create('/settings/credentials/personal', 'POST');
        $request->setUserResolver(static fn (): User => $user);
        $surface = app(PersonalCredentialSurface::class);

        foreach ([
            fn () => app(UiCredentialPurposes::class)->purposeForSubmission('test.consume'),
            fn () => $surface->mintMineForPurpose($request, CredentialPurpose::Signing, new MintOptions(kind: CredentialKind::Hmac)),
            fn () => $surface->mintMineForPurpose($request, CredentialPurpose::Consumption, new MintOptions(kind: CredentialKind::Hmac)),
        ] as $index => $action) {
            if ($index === 1) {
                UiPersonalCredentialDeclaration::$kinds = [CredentialKind::Bearer];
            } else {
                UiPersonalCredentialDeclaration::$kinds = CredentialKind::cases();
            }
            $before = $this->effects();
            try {
                $action();
                $this->fail('Expected the flags-off direct refusal.');
            } catch (InvalidCredentialInput|CredentialVerbRefused) {
                $this->assertSame($before, $this->effects());
            }
        }

        foreach ([CredentialVerb::Issue, CredentialVerb::Rotate, CredentialVerb::Revoke] as $verb) {
            UiPersonalCredentialDeclaration::$deniedVerbs = [$verb];
            $before = $this->effects();

            try {
                match ($verb) {
                    CredentialVerb::Issue => $surface->mintMineForPurpose($request, CredentialPurpose::Consumption, new MintOptions),
                    CredentialVerb::Rotate => $surface->rotateMine($request, $credential->id, new RotateOptions),
                    CredentialVerb::Revoke => $surface->revokeMine($request, $credential->id),
                    default => throw new \LogicException('Unexpected verb.'),
                };
                $this->fail('Expected the flags-off declaration refusal.');
            } catch (CredentialVerbRefused) {
                $this->assertSame($before, $this->effects());
            }
        }
    }

    public function test_personal_flag_changes_only_navigation_and_not_authorized_issue_effects(): void
    {
        $observed = [];

        foreach ([false, true] as $enabled) {
            config(['built-for-cloud.ui.personal_credentials' => $enabled]);
            $user = $this->user(UserRole::Admin);
            $home = $this->actingAsVersioned($user, 'web')->get(route('bfc.ui.home'))->assertOk();
            $this->assertSame($enabled ? 1 : 0, substr_count(
                (string) $home->getContent(),
                'data-testid="ui-nav-personal-credentials"',
            ));

            $before = $this->effects();
            $page = $this->get(route('bfc.ui.personal-credentials.index'))->assertOk();
            $response = $this->post(route('bfc.ui.personal-credentials.store'), [
                SubmissionNonce::FIELD => $this->submissionNonce($page, route('bfc.ui.personal-credentials.store')),
                'app_purpose' => 'test.consume',
                'kind' => 'bearer',
                'name' => 'test-created-flag-'.($enabled ? 'on' : 'off'),
            ])->assertCreated();
            $observed[] = [
                'delta' => array_map(
                    static fn (int $count, string $key): int => $count - $before[$key],
                    $this->effects(),
                    array_keys($before),
                ),
                'shape' => $response->getStatusCode(),
            ];
        }

        $this->assertSame($observed[0], $observed[1]);
    }

    public function test_invalid_csrf_refuses_issue_rotate_and_revoke_without_effect(): void
    {
        $user = $this->user(UserRole::Member);
        $credential = $this->personalCredential($user);
        $this->actingAsVersioned($user, 'web');
        app()->instance('env', 'local');

        foreach ([false, true] as $flagsOff) {
            if ($flagsOff) {
                $this->allFlagsOff();
            }

            foreach ([
                fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.store'), [
                    'app_purpose' => 'test.consume', 'kind' => 'bearer', '_token' => 'invalid',
                ]),
                fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $credential->id), ['_token' => 'invalid']),
                fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $credential->id), ['_token' => 'invalid']),
            ] as $request) {
                $before = $this->effects();
                $request()->assertStatus(419)->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
                $this->assertSame($before, $this->effects());
            }
        }
    }

    public function test_stale_and_denied_managed_memberships_refuse_every_personal_verb_with_flags_on_or_off(): void
    {
        $this->setManagedAuthority();
        Http::fake(Http::response([], 503));

        foreach (['removed', 'disabled', 'stale'] as $state) {
            foreach ([false, true] as $flagsOff) {
                if ($flagsOff) {
                    $this->allFlagsOff();
                } else {
                    config([
                        'built-for-cloud.ui.personal_credentials' => true,
                        'built-for-cloud.ui.credential_purposes' => [
                            'test.consume', 'test.mcp', 'test.sign', 'test.enroll',
                        ],
                    ]);
                }

                $user = $this->managedUser($state);
                $credential = $this->personalCredential($user);
                $this->actingAsVersioned($user, 'web');

                foreach ([
                    fn (): TestResponse => $this->get(route('bfc.ui.personal-credentials.index')),
                    fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.store'), [
                        'app_purpose' => 'test.consume', 'kind' => 'bearer',
                    ]),
                    fn (): TestResponse => $this->post(route('bfc.ui.personal-credentials.rotate', $credential->id)),
                    fn (): TestResponse => $this->delete(route('bfc.ui.personal-credentials.destroy', $credential->id)),
                ] as $request) {
                    $before = $this->effects();
                    $request()->assertRedirect()->assertDontSeeHtml('data-testid="personal-credentials-delivery"');
                    $this->assertSame($before, $this->effects());
                }
            }
        }
    }

    public function test_routes_remain_mounted_with_flags_off_and_pin_exact_middleware(): void
    {
        $this->allFlagsOff();
        $expected = [
            'bfc.ui.personal-credentials.index' => ['GET', 'settings/credentials/personal'],
            'bfc.ui.personal-credentials.store' => ['POST', 'settings/credentials/personal'],
            'bfc.ui.personal-credentials.rotate' => ['POST', 'settings/credentials/personal/{id}/rotate'],
            'bfc.ui.personal-credentials.destroy' => ['DELETE', 'settings/credentials/personal/{id}'],
        ];
        /** @var Router $router */
        $router = app('router');

        foreach ($expected as $name => [$method, $uri]) {
            $route = Route::getRoutes()->getByName($name);
            $this->assertNotNull($route);
            $this->assertSame($method, $route->methods()[0]);
            $this->assertSame($uri, $route->uri());
            $this->assertContains('throttle:bfc-personal', $route->middleware());
            $middleware = $router->gatherRouteMiddleware($route);
            $this->assertContains(StartSession::class, $middleware);
            $this->assertContains(PreventRequestForgery::class, $middleware);
        }
    }

    /** @return array{credentials: int, audits: int, outbox: int, tokens: int} */
    private function effects(): array
    {
        return [
            'credentials' => Credential::query()->count(),
            'audits' => CredentialAuditEvent::query()->count(),
            'outbox' => CredentialOutboxEntry::query()->count(),
            'tokens' => OnboardingToken::query()->count(),
        ];
    }

    private function allFlagsOff(): void
    {
        config([
            'built-for-cloud.ui.member_management' => false,
            'built-for-cloud.ui.personal_credentials' => false,
            'built-for-cloud.ui.installation_credentials' => false,
            'built-for-cloud.ui.session_management' => false,
            'built-for-cloud.ui.managed_transitions' => false,
            'built-for-cloud.ui.credential_purposes' => [],
        ]);
    }

    private function setManagedAuthority(): void
    {
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'mode' => AuthorityMode::Managed->value,
            'generation' => 2,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'ui-connection',
            'organization_id' => 'ui-organization',
            'installation_id' => 'ui-installation',
            'authority_base_url' => 'https://authority.example.test',
            'managed_connection_status' => 'active',
            'managed_connection_generation' => 2,
            'managed_connection_roster_version' => 3,
            'managed_connection_response_sequence' => 4,
        ]);
    }

    private function managedUser(string $state): User
    {
        $user = $this->user(UserRole::Member);
        $user->forceFill([
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'ui-connection',
            'scalpels_id' => 'subject-'.$user->getKey(),
            'managed_membership_status' => $state === 'stale' ? 'active' : $state,
            'managed_membership_role' => UserRole::Member->value,
            'managed_membership_generation' => 2,
            'managed_membership_roster_version' => 3,
            'managed_membership_response_sequence' => 4,
            'managed_membership_responded_at' => now()->toAtomString(),
            'membership_confirmed_at' => $state === 'stale' ? now()->subHour() : now(),
        ])->save();

        return $user;
    }

    private function user(UserRole $role): User
    {
        $user = User::query()->create([
            'name' => 'Test-created '.$role->value,
            'email' => bin2hex(random_bytes(6)).'@example.test',
            'password' => bcrypt('test-created-password'),
        ]);
        $user->forceFill([
            'role' => $role->value,
            'status' => 'active',
            'email_verified_at' => now(),
        ])->save();

        return $user;
    }

    /** @param array<string, mixed> $attributes */
    private function personalCredential(User $user, array $attributes = []): Credential
    {
        return Credential::query()->create(array_merge([
            'kind' => CredentialKind::Bearer,
            'purpose' => CredentialPurpose::Consumption,
            'subject_type' => SubjectType::UserPrincipal,
            'subject_ref' => 'ui-user:'.$user->getKey(),
            'user_id' => (string) $user->getKey(),
            'name' => 'test-created-existing-'.$user->getKey(),
            'abilities' => [OperatorAbility::McpRead->value],
            'status' => CredentialStatus::Active,
            'secret_hash' => hash('sha256', 'test-created-secret-'.$user->getKey()),
        ], $attributes));
    }

    private function activeAsymmetric(User $user, string $name): Credential
    {
        return Credential::query()->create([
            'kind' => CredentialKind::Asymmetric,
            'purpose' => CredentialPurpose::Enrollment,
            'subject_type' => SubjectType::UserPrincipal,
            'subject_ref' => 'ui-user:'.$user->getKey(),
            'user_id' => (string) $user->getKey(),
            'name' => $name,
            'abilities' => [OperatorAbility::McpRead->value],
            'status' => CredentialStatus::Active,
            'public_key' => CredentialFactory::generatePublicKey(),
        ]);
    }

    private function deliverySecret(TestResponse $response, CredentialKind $kind): string
    {
        $label = match ($kind) {
            CredentialKind::Bearer => 'secret',
            CredentialKind::Basic => 'password',
            CredentialKind::Hmac => 'signing_key',
            CredentialKind::Asymmetric => 'enrollment_code',
        };
        $matched = preg_match(
            '/<strong>'.preg_quote($label, '/').'<\/strong>:\s*<code>([^<]+)<\/code>/',
            (string) $response->getContent(),
            $matches,
        );
        $this->assertSame(1, $matched);

        return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5);
    }

    private function submissionNonce(TestResponse $response, string $action): string
    {
        $matched = preg_match(
            '/<form[^>]+action="'.preg_quote($action, '/').'".*?name="submission_nonce" value="([a-f0-9]{64})"/s',
            (string) $response->getContent(),
            $matches,
        );
        $this->assertSame(1, $matched, 'Expected a server-minted submission nonce for '.$action.'.');

        return $matches[1];
    }

    private function activateHmac(Credential $credential, TestResponse $delivery): void
    {
        preg_match('/<strong>delivery_fingerprint<\/strong>:\s*<code>([^<]+)<\/code>/', (string) $delivery->getContent(), $matches);
        $this->postJson('/bfc/credentials/'.$credential->id.'/activate', [
            'delivery_fingerprint' => html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5),
        ], [
            'Authorization' => 'Bearer '.auditOperatorCredential(
                'ui-hmac-activation-'.bin2hex(random_bytes(4)),
                [OperatorAbility::CredentialRotate->value],
            ),
        ])->assertOk();
    }

    private function assertSecretAuthenticates(Credential $credential, string $secret, CredentialPurpose $purpose): void
    {
        $this->credentialAuthRoute();
        $header = $credential->kind === CredentialKind::Basic
            ? 'Basic '.base64_encode($credential->id.':'.$secret)
            : 'Bearer '.$secret;
        $this->getJson('/p5-ui-d/credential-auth/'.$purpose->value, ['Authorization' => $header])
            ->assertOk()
            ->assertJsonPath('credential_id', $credential->id);
    }

    private function assertSecretDoesNotAuthenticate(Credential $credential, string $secret, CredentialPurpose $purpose): void
    {
        $this->credentialAuthRoute();
        $header = $credential->kind === CredentialKind::Basic
            ? 'Basic '.base64_encode($credential->id.':'.$secret)
            : 'Bearer '.$secret;
        $this->getJson('/p5-ui-d/credential-auth/'.$purpose->value, ['Authorization' => $header])->assertUnauthorized();
    }

    private function credentialAuthRoute(): void
    {
        if (Route::getRoutes()->getByName('p5-ui-d.credential-auth') !== null) {
            return;
        }

        Route::get('/p5-ui-d/credential-auth/{purpose}', static function (string $purpose): array {
            $guard = Auth::guard('bfc');

            if (! $guard instanceof CredentialGuard) {
                abort(500);
            }

            $credential = $guard->credentialForPurposes([CredentialPurpose::from($purpose)]);

            if ($credential === null) {
                abort(401);
            }

            return ['credential_id' => $credential->id];
        })->name('p5-ui-d.credential-auth');
    }

    private function assertHmacAuthenticates(User $user, string $id, string $secret): void
    {
        $this->hmacRequest($user, $id, $secret)->assertOk()->assertJsonPath('credential_id', $id);
    }

    private function assertHmacDoesNotAuthenticate(User $user, string $id, string $secret): void
    {
        $this->hmacRequest($user, $id, $secret)->assertUnauthorized();
    }

    private function hmacRequest(User $user, string $id, string $secret): TestResponse
    {
        if (Route::getRoutes()->getByName('p5-ui-d.hmac-auth') === null) {
            Route::post('/p5-ui-d/hmac-auth/{user}', static function (Request $request): array {
                return ['credential_id' => $request->attributes->get('bfc.hmac_credential_id')];
            })->middleware('bfc.hmac')->name('p5-ui-d.hmac-auth');
        }

        $body = '{"test-created":"p5-ui-d"}';
        $envelope = new HmacEnvelope(
            keyId: $id,
            eventType: 'p5-ui-d.test',
            timestamp: now()->getTimestamp(),
            nonce: bin2hex(random_bytes(16)),
            audience: (string) config('built-for-cloud.hmac.audience'),
        );

        return $this->call('POST', '/p5-ui-d/hmac-auth/'.$user->getKey(), server: [
            'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $envelope->headerValue(hash_hmac(
                'sha256',
                $envelope->canonical($body),
                $secret,
            )),
            'CONTENT_TYPE' => 'application/json',
        ], content: $body);
    }
}
