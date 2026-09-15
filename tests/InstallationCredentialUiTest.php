<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialManagementScope;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiInstallationCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;

final class InstallationCredentialUiTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        UiInstallationCredentialDeclaration::$hmacSubject = null;

        config([
            'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
            'built-for-cloud.credentials.declaration' => UiInstallationCredentialDeclaration::class,
            'built-for-cloud.credentials.app_purposes' => [
                'test.deploy' => CredentialPurpose::SystemDeployment->value,
                'test.ingest' => CredentialPurpose::Consumption->value,
                'test.mcp' => CredentialPurpose::Mcp->value,
                'test.sign' => CredentialPurpose::Signing->value,
                'test.enroll' => CredentialPurpose::Enrollment->value,
                'test.hidden' => CredentialPurpose::SystemDeployment->value,
            ],
            'built-for-cloud.ui.credential_purposes' => [
                'test.deploy', 'test.ingest', 'test.mcp', 'test.sign', 'test.enroll',
            ],
            'built-for-cloud.ui.installation_credentials' => true,
            'built-for-cloud.manifest' => [
                'name' => 'Test-created installation credential application',
                'slug' => 'test-created-installation-credential-application',
                'description' => 'Test-created installation credential description',
                'icon' => 'https://assets.example.test/installation-credential.svg',
                'product_url' => 'https://scalpels.app/products/test-created-installation-credential-application',
            ],
        ]);
    }

    /** @return iterable<string, array{UserRole, string, CredentialPurpose, CredentialKind, SubjectType}> */
    public static function rolePurposeKindSubjectProvider(): iterable
    {
        $pairs = [
            ['test.deploy', CredentialPurpose::SystemDeployment, CredentialKind::Bearer, [SubjectType::Application, SubjectType::Installation]],
            ['test.deploy', CredentialPurpose::SystemDeployment, CredentialKind::Basic, [SubjectType::Application, SubjectType::Installation]],
            ['test.ingest', CredentialPurpose::Consumption, CredentialKind::Bearer, [SubjectType::Installation]],
            ['test.ingest', CredentialPurpose::Consumption, CredentialKind::Basic, [SubjectType::Installation]],
            ['test.mcp', CredentialPurpose::Mcp, CredentialKind::Bearer, [SubjectType::Installation]],
            ['test.mcp', CredentialPurpose::Mcp, CredentialKind::Basic, [SubjectType::Installation]],
            ['test.sign', CredentialPurpose::Signing, CredentialKind::Hmac, [SubjectType::Application, SubjectType::Installation]],
            ['test.enroll', CredentialPurpose::Enrollment, CredentialKind::Asymmetric, [SubjectType::Application, SubjectType::Installation]],
        ];

        foreach (UserRole::cases() as $role) {
            foreach ($pairs as [$appPurpose, $purpose, $kind, $subjectTypes]) {
                foreach ($subjectTypes as $subjectType) {
                    yield implode('-', [$role->value, $appPurpose, $kind->value, $subjectType->value]) => [
                        $role, $appPurpose, $purpose, $kind, $subjectType,
                    ];
                }
            }
        }
    }

    public function test_consumption_and_mcp_choices_offer_only_the_installation_subject(): void
    {
        $actor = $this->user(UserRole::Member);
        $page = $this->actingAsVersioned($actor, 'web')
            ->get(route('bfc.ui.installation-credentials.index'))
            ->assertOk();
        preg_match_all(
            '/<form data-testid="installation-credentials-issue-option".*?<\/form>/s',
            (string) $page->getContent(),
            $matches,
        );
        $observed = [];

        foreach ($matches[0] as $form) {
            if (! str_contains($form, 'value="test.ingest"') && ! str_contains($form, 'value="test.mcp"')) {
                continue;
            }

            preg_match('/name="app_purpose" value="([^"]+)"/', $form, $purpose);
            preg_match('/name="kind" value="([^"]+)"/', $form, $kind);
            $this->assertArrayHasKey(1, $purpose);
            $this->assertArrayHasKey(1, $kind);
            $this->assertStringContainsString('value="installation"', $form);
            $this->assertStringNotContainsString('value="application"', $form);
            $observed[] = $purpose[1].' / '.$kind[1];
        }

        sort($observed);

        $this->assertSame([
            'test.ingest / basic',
            'test.ingest / bearer',
            'test.mcp / basic',
            'test.mcp / bearer',
        ], $observed);
    }

    #[DataProvider('rolePurposeKindSubjectProvider')]
    public function test_every_role_and_admitted_shape_issues_lists_cross_issuer_rotates_and_revokes(
        UserRole $role,
        string $appPurpose,
        CredentialPurpose $purpose,
        CredentialKind $kind,
        SubjectType $subjectType,
    ): void {
        $actor = $this->user($role);
        $issuer = $this->user(UserRole::Member);
        $prefix = implode('-', [$role->value, str_replace('.', '-', $appPurpose), $kind->value, $subjectType->value]);

        $page = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.installation-credentials.index'));
        $page->assertOk()
            ->assertSeeHtml('data-testid="installation-credentials"')
            ->assertSee($appPurpose)
            ->assertSee($kind->value)
            ->assertSee($subjectType->value);
        $this->assertSame(1, substr_count((string) $page->getContent(), '<main>'));

        [$issued, $secret, $issue] = $this->issue(
            $actor,
            $appPurpose,
            $kind,
            $subjectType,
            $prefix.'-owned',
            $prefix.'-owned-subject',
            true,
        );
        $this->assertSame($purpose, $issued->purpose);
        $this->assertSame($kind, $issued->kind);
        $this->assertSame($subjectType, $issued->subject_type);
        $this->assertSame($prefix.'-owned-subject', $issued->subject_ref);
        $this->assertNull($issued->user_id);
        $this->assertNull($issued->abilities);
        $this->assertImmediateReveal($issue, $secret);
        $this->prepareForUse($issued, $issue);
        $this->assertCredentialUsable($issued, $secret, true);

        $revisit = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.installation-credentials.index'));
        $revisit->assertOk()
            ->assertSee($issued->name)
            ->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
        $this->assertStringNotContainsString($secret, (string) $revisit->getContent());

        [$source, $sourceSecret, $sourceDelivery] = $this->issue(
            $issuer,
            $appPurpose,
            $kind,
            $subjectType,
            $prefix.'-cross-rotate',
            $prefix.'-cross-rotate-subject',
        );
        $this->prepareForUse($source, $sourceDelivery);
        $this->assertCredentialUsable($source, $sourceSecret, true);
        $source = $source->refresh();

        $this->actingAsVersioned($actor, 'web');
        $rotatePayload = $kind === CredentialKind::Asymmetric
            ? ['code_ttl_seconds' => 120, 'abilities' => [OperatorAbility::Admin->value], 'emergency' => true]
            : ['abilities' => [OperatorAbility::Admin->value], 'emergency' => true];
        $rotatePayload[SubmissionNonce::FIELD] = $this->nonceFor(
            route('bfc.ui.installation-credentials.rotate', $source->id),
        );
        $rotate = $this->post(
            route('bfc.ui.installation-credentials.rotate', $source->id),
            $rotatePayload,
        )->assertStatus(201)
            ->assertSeeHtml('data-testid="installation-credentials-delivery"');
        $replacement = Credential::query()->where('name', $source->name)->whereKeyNot($source->id)->sole();
        $rotationSecret = $this->deliverySecret($rotate, $kind);
        $this->assertImmediateReveal($rotate, $rotationSecret);
        $this->assertSame($source->purpose, $replacement->purpose);
        $this->assertSame($source->subject_type, $replacement->subject_type);
        $this->assertSame($source->subject_ref, $replacement->subject_ref);
        $this->assertSame($source->user_id, $replacement->user_id);
        $this->assertSame($source->abilities, $replacement->abilities);
        $this->assertSame($source->name, $replacement->name);
        $this->assertSame($source->expires_at?->toAtomString(), $replacement->expires_at?->toAtomString());
        $this->assertNotNull($source->refresh()->rotated_at);
        $this->assertAuditActor($source, LifecycleEventType::Issued, $issuer);
        $this->assertAuditActor($source, LifecycleEventType::Rotated, $actor);
        $this->prepareForUse($replacement, $rotate);
        $this->assertCredentialUsable($replacement, $rotationSecret, true);

        $postRotateRevisit = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.installation-credentials.index'));
        $postRotateRevisit->assertOk()->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
        $this->assertStringNotContainsString($rotationSecret, (string) $postRotateRevisit->getContent());

        [$revokeTarget, $revokeSecret, $revokeDelivery] = $this->issue(
            $issuer,
            $appPurpose,
            $kind,
            $subjectType,
            $prefix.'-cross-revoke',
            $prefix.'-cross-revoke-subject',
        );
        $this->prepareForUse($revokeTarget, $revokeDelivery);
        $this->assertCredentialUsable($revokeTarget, $revokeSecret, true);
        $this->actingAsVersioned($actor, 'web')
            ->delete(route('bfc.ui.installation-credentials.destroy', $revokeTarget->id))
            ->assertRedirect(route('bfc.ui.installation-credentials.index'))
            ->assertStatus(303);
        $this->assertNotNull($revokeTarget->refresh()->revoked_at);
        $this->assertAuditActor($revokeTarget, LifecycleEventType::Issued, $issuer);
        $this->assertAuditActor($revokeTarget, LifecycleEventType::Revoked, $actor);
        $this->assertCredentialUsable($revokeTarget, $revokeSecret, false);
    }

    public function test_member_installation_scope_lists_only_contained_rows_and_hides_their_ids_on_mutation(): void
    {
        $actor = $this->user(UserRole::Member);
        $application = $this->storedCredential(SubjectType::Application, 'included-application');
        $installation = $this->storedCredential(SubjectType::Installation, 'included-installation');
        $personal = $this->storedCredential(SubjectType::UserPrincipal, 'excluded-personal', userId: (string) $actor->getKey());
        $operatorAbilities = $this->storedCredential(
            SubjectType::Application,
            'excluded-operator-ability',
            abilities: [OperatorAbility::Admin->value],
        );
        $root = $this->signingRoot();
        $scope = CredentialManagementScope::memberInstallation();

        $page = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.installation-credentials.index'));
        $page->assertOk()
            ->assertSee($application->name)
            ->assertSee($installation->name)
            ->assertDontSee($personal->name)
            ->assertDontSee($operatorAbilities->name)
            ->assertDontSee($root->name);

        $listed = collect(app(ListCredentials::class)(managementScope: $scope))->pluck('id')->all();
        $this->assertEqualsCanonicalizing([$application->id, $installation->id], $listed);
        $this->assertSame([SubjectType::Application->value, SubjectType::Installation->value], $scope->subjectTypes());
        $this->assertSame(OperatorAbility::Admin->value, $scope->firstExcludedAbility([OperatorAbility::Admin->value]));

        $unknown = (string) Str::uuid();
        $unknownRotate = $this->post(route('bfc.ui.installation-credentials.rotate', $unknown));
        $unknownDestroy = $this->delete(route('bfc.ui.installation-credentials.destroy', $unknown));

        foreach ([$personal, $operatorAbilities, $root] as $excluded) {
            $before = $this->effects();
            $rotate = $this->post(route('bfc.ui.installation-credentials.rotate', $excluded->id));
            $this->assertSame($unknownRotate->getStatusCode(), $rotate->getStatusCode());
            $this->assertSame($unknownRotate->getContent(), $rotate->getContent());
            $this->assertSame($before, $this->effects());

            $destroy = $this->delete(route('bfc.ui.installation-credentials.destroy', $excluded->id));
            $this->assertSame($unknownDestroy->getStatusCode(), $destroy->getStatusCode());
            $this->assertSame($unknownDestroy->getContent(), $destroy->getContent());
            $this->assertSame($before, $this->effects());
        }
    }

    public function test_browser_input_refusals_have_zero_effect_and_raw_authority_fields_cannot_widen_storage(): void
    {
        $actor = $this->user(UserRole::Admin);
        $this->actingAsVersioned($actor, 'web');

        foreach ([
            'missing purpose' => [],
            'malformed purpose' => ['app_purpose' => ['test.deploy']],
            'unoffered purpose' => ['app_purpose' => 'test.hidden'],
            'unmapped purpose' => ['app_purpose' => 'test.unmapped'],
            'unknown kind' => ['app_purpose' => 'test.deploy', 'kind' => 'unknown'],
            'inadmissible pair' => ['app_purpose' => 'test.deploy', 'kind' => CredentialKind::Hmac->value],
        ] as $label => $payload) {
            config(['built-for-cloud.ui.credential_purposes' => [
                'test.deploy', 'test.sign', 'test.enroll', 'test.unmapped',
            ]]);
            $before = $this->effects();
            $response = $this->post(route('bfc.ui.installation-credentials.store'), [
                'subject_type' => SubjectType::Application->value,
                'subject_ref' => 'refused-'.$label,
                ...$payload,
            ])->assertUnprocessable()->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
            $this->assertSame($before, $this->effects(), $label.' '.$response->getStatusCode());
        }

        $before = $this->effects();
        $this->post(route('bfc.ui.installation-credentials.store'), [
            'app_purpose' => 'test.sign',
            'kind' => CredentialKind::Hmac->value,
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => SigningRootMac::SUBJECT_REF,
        ])->assertForbidden()->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
        $this->assertSame($before, $this->effects());

        $this->post(route('bfc.ui.installation-credentials.store'), [
            'app_purpose' => 'test.deploy',
            'kind' => CredentialKind::Bearer->value,
            'subject_type' => SubjectType::Application->value,
            'subject_ref' => 'raw-fields-ignored',
            'purpose' => CredentialPurpose::SigningRoot->value,
            'abilities' => [OperatorAbility::Admin->value],
            'user_id' => (string) $actor->getKey(),
            'root' => SigningRootMac::SUBJECT_REF,
            'name' => 'raw-fields-ignored',
            SubmissionNonce::FIELD => $this->nonceFor(route('bfc.ui.installation-credentials.store')),
        ])->assertStatus(201)
            ->assertSeeHtml('data-testid="installation-credentials-delivery"');
        $credential = Credential::query()->where('name', 'raw-fields-ignored')->sole();
        $this->assertSame(CredentialPurpose::SystemDeployment, $credential->purpose);
        $this->assertNull($credential->abilities);
        $this->assertNull($credential->user_id);
        $this->assertSame(SubjectType::Application, $credential->subject_type);
        $this->assertSame('raw-fields-ignored', $credential->subject_ref);
    }

    public function test_unknown_role_refuses_every_browser_verb_without_effect(): void
    {
        $unknown = $this->user('future-role');
        $credential = $this->storedCredential(SubjectType::Installation, 'unknown-role-target');

        foreach ([
            fn (): TestResponse => $this->actingAsVersioned($unknown, 'web')->get(route('bfc.ui.installation-credentials.index')),
            fn (): TestResponse => $this->actingAsVersioned($unknown, 'web')->post(route('bfc.ui.installation-credentials.store'), [
                'app_purpose' => 'test.deploy',
                'kind' => CredentialKind::Bearer->value,
                'subject_type' => SubjectType::Installation->value,
                'subject_ref' => 'unknown-role-issue',
            ]),
            fn (): TestResponse => $this->actingAsVersioned($unknown, 'web')->post(route('bfc.ui.installation-credentials.rotate', $credential->id)),
            fn (): TestResponse => $this->actingAsVersioned($unknown, 'web')->delete(route('bfc.ui.installation-credentials.destroy', $credential->id)),
        ] as $request) {
            $before = $this->effects();
            $request()->assertForbidden()->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }
    }

    public function test_installation_flag_changes_only_navigation_and_not_authorized_issue_effects(): void
    {
        $observed = [];

        foreach ([false, true] as $enabled) {
            config(['built-for-cloud.ui.installation_credentials' => $enabled]);
            $actor = $this->user(UserRole::Admin);
            $home = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.home'))->assertOk();
            $this->assertSame($enabled ? 1 : 0, substr_count(
                (string) $home->getContent(),
                'data-testid="ui-nav-installation-credentials"',
            ));

            $before = $this->effectCounts();
            $response = $this->post(route('bfc.ui.installation-credentials.store'), [
                'app_purpose' => 'test.deploy',
                'kind' => CredentialKind::Bearer->value,
                'subject_type' => SubjectType::Installation->value,
                'subject_ref' => 'flag-'.($enabled ? 'on' : 'off'),
                'name' => 'flag-'.($enabled ? 'on' : 'off'),
                SubmissionNonce::FIELD => $this->nonceFor(route('bfc.ui.installation-credentials.store')),
            ])->assertStatus(201)
                ->assertSeeHtml('data-testid="installation-credentials-delivery"');
            $observed[] = [
                'delta' => array_map(
                    static fn (int $count, string $key): int => $count - $before[$key],
                    $this->effectCounts(),
                    array_keys($before),
                ),
                'status' => $response->getStatusCode(),
            ];
        }

        $this->assertSame($observed[0], $observed[1]);
    }

    public function test_issue_and_rotate_deliver_immediately_and_replay_or_revisit_never_reveals_or_repeats_effects(): void
    {
        $actor = $this->user(UserRole::Member);
        $this->actingAsVersioned($actor, 'web');

        $issuePayload = [
            'app_purpose' => 'test.deploy',
            'kind' => CredentialKind::Bearer->value,
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'test-created-refresh-proof',
            'name' => 'test-created-refresh-proof',
            SubmissionNonce::FIELD => $this->nonceFor(route('bfc.ui.installation-credentials.store')),
        ];
        $issueDelivery = $this->post(route('bfc.ui.installation-credentials.store'), $issuePayload)
            ->assertStatus(201)
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSeeHtml('data-testid="installation-credentials-delivery"');

        $afterIssue = $this->effects();
        $issueSecret = $this->deliverySecret($issueDelivery, CredentialKind::Bearer);

        $this->post(route('bfc.ui.installation-credentials.store'), $issuePayload)
            ->assertStatus(409)
            ->assertDontSeeHtml('data-testid="installation-credentials-delivery"')
            ->assertDontSee($issueSecret);
        $this->assertSame($afterIssue, $this->effects());

        foreach ([1, 2] as $revisit) {
            $this->get(route('bfc.ui.installation-credentials.index'))
                ->assertOk()
                ->assertHeader('Cache-Control', 'no-store, private')
                ->assertDontSeeHtml('data-testid="installation-credentials-delivery"')
                ->assertDontSee($issueSecret);
        }
        $this->assertSame($afterIssue, $this->effects());

        $issued = Credential::query()->where('name', 'test-created-refresh-proof')->sole();
        $rotatePayload = [SubmissionNonce::FIELD => $this->nonceFor(
            route('bfc.ui.installation-credentials.rotate', $issued->id),
        )];
        $rotateDelivery = $this->post(route('bfc.ui.installation-credentials.rotate', $issued->id), $rotatePayload)
            ->assertStatus(201)
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSeeHtml('data-testid="installation-credentials-delivery"');

        $afterRotate = $this->effects();
        $rotationSecret = $this->deliverySecret($rotateDelivery, CredentialKind::Bearer);

        $this->post(route('bfc.ui.installation-credentials.rotate', $issued->id), $rotatePayload)
            ->assertStatus(409)
            ->assertDontSeeHtml('data-testid="installation-credentials-delivery"')
            ->assertDontSee($rotationSecret);
        $this->assertSame($afterRotate, $this->effects());

        foreach ([1, 2] as $revisit) {
            $this->get(route('bfc.ui.installation-credentials.index'))
                ->assertOk()
                ->assertDontSeeHtml('data-testid="installation-credentials-delivery"')
                ->assertDontSee($rotationSecret);
        }
        $this->assertSame($afterRotate, $this->effects());
    }

    public function test_submission_nonce_refuses_every_binding_mismatch_without_effect_or_delivery(): void
    {
        $actor = $this->user(UserRole::Member);
        $other = $this->user(UserRole::Member);
        $first = $this->storedCredential(SubjectType::Installation, 'nonce-first');
        $second = $this->storedCredential(SubjectType::Installation, 'nonce-second');
        $this->actingAsVersioned($actor, 'web');
        $sessionId = $this->app['session']->getId();
        $issuePayload = [
            'app_purpose' => 'test.deploy',
            'kind' => CredentialKind::Bearer->value,
            'subject_type' => SubjectType::Installation->value,
            'subject_ref' => 'nonce-refusal',
        ];

        $cases = [
            'missing' => null,
            'foreign session' => SubmissionNonce::issue('foreign-session', (string) $actor->getKey(), CredentialVerb::Issue, 'installation-credentials'),
            'wrong user' => SubmissionNonce::issue($sessionId, (string) $other->getKey(), CredentialVerb::Issue, 'installation-credentials'),
            'wrong verb' => SubmissionNonce::issue($sessionId, (string) $actor->getKey(), CredentialVerb::Rotate, 'installation-credentials'),
            'wrong target' => SubmissionNonce::issue($sessionId, (string) $actor->getKey(), CredentialVerb::Issue, 'another-target'),
        ];

        foreach ($cases as $label => $nonce) {
            $before = $this->effects();
            $payload = $issuePayload;

            if ($nonce !== null) {
                $payload[SubmissionNonce::FIELD] = $nonce;
            }

            $this->post(route('bfc.ui.installation-credentials.store'), $payload)
                ->assertStatus(409)
                ->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
            $this->assertSame($before, $this->effects(), $label);
        }

        $wrongTarget = SubmissionNonce::issue(
            $sessionId,
            (string) $actor->getKey(),
            CredentialVerb::Rotate,
            $first->id,
        );
        $before = $this->effects();
        $this->post(route('bfc.ui.installation-credentials.rotate', $second->id), [
            SubmissionNonce::FIELD => $wrongTarget,
        ])->assertStatus(409)->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
        $this->assertSame($before, $this->effects());

        $expired = SubmissionNonce::issue(
            $sessionId,
            (string) $actor->getKey(),
            CredentialVerb::Rotate,
            $first->id,
        );
        $this->travel(3601)->seconds();
        $before = $this->effects();
        $this->post(route('bfc.ui.installation-credentials.rotate', $first->id), [
            SubmissionNonce::FIELD => $expired,
        ])->assertStatus(409)->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
        $this->assertSame($before, $this->effects());
    }

    public function test_every_refusal_retains_zero_effect_with_all_flags_off_and_no_ui_purposes(): void
    {
        $actor = $this->user(UserRole::Member);
        $unknownRole = $this->user('future-role');
        $personal = $this->storedCredential(SubjectType::UserPrincipal, 'flags-off-personal', userId: (string) $actor->getKey());
        $operatorAbilities = $this->storedCredential(
            SubjectType::Application,
            'flags-off-operator-ability',
            abilities: [OperatorAbility::Admin->value],
        );
        $root = $this->signingRoot();
        $manageable = $this->storedCredential(SubjectType::Installation, 'flags-off-manageable');
        $this->allFlagsOff();

        $home = $this->actingAsVersioned($actor, 'web')->get(route('bfc.ui.home'))->assertOk();
        $home->assertDontSeeHtml('data-testid="ui-nav-installation-credentials"');
        $this->get(route('bfc.ui.installation-credentials.index'))->assertOk()->assertSee($manageable->name);

        $this->assertFalse(RolePolicy::canManageInstallationCredentials($unknownRole->role));
        foreach ([
            fn (): TestResponse => $this->actingAsVersioned($unknownRole, 'web')->get(route('bfc.ui.installation-credentials.index')),
            fn (): TestResponse => $this->actingAsVersioned($unknownRole, 'web')->post(route('bfc.ui.installation-credentials.store'), []),
            fn (): TestResponse => $this->actingAsVersioned($unknownRole, 'web')->post(route('bfc.ui.installation-credentials.rotate', $manageable->id)),
            fn (): TestResponse => $this->actingAsVersioned($unknownRole, 'web')->delete(route('bfc.ui.installation-credentials.destroy', $manageable->id)),
        ] as $request) {
            $before = $this->effects();
            $request()->assertForbidden();
            $this->assertSame($before, $this->effects());
        }

        $this->actingAsVersioned($actor, 'web');
        foreach ([$personal, $operatorAbilities, $root] as $excluded) {
            foreach ([
                fn (): TestResponse => $this->post(route('bfc.ui.installation-credentials.rotate', $excluded->id)),
                fn (): TestResponse => $this->delete(route('bfc.ui.installation-credentials.destroy', $excluded->id)),
            ] as $request) {
                $before = $this->effects();
                $request()->assertNotFound();
                $this->assertSame($before, $this->effects());
            }
        }

        $before = $this->effects();
        $this->postJson('/bfc/installation/credentials', [
            'subject_type' => SubjectType::Application->value,
            'subject_ref' => 'flags-off-excluded-ability',
            'purpose' => CredentialPurpose::SystemDeployment->value,
            'abilities' => [OperatorAbility::Admin->value],
        ])->assertForbidden();
        $this->assertSame($before, $this->effects());

        foreach (['test.hidden', 'test.unmapped'] as $appPurpose) {
            $before = $this->effects();
            try {
                app(UiCredentialPurposes::class)->purposeForSubmission($appPurpose);
                $this->fail('Expected the flags-off purpose refusal for '.$appPurpose.'.');
            } catch (InvalidCredentialInput) {
                $this->assertSame($before, $this->effects());
            }
        }

        $before = $this->effects();
        try {
            app(AppPurposeRegistry::class)->purpose('test.unmapped');
            $this->fail('Expected the unmapped protocol purpose refusal.');
        } catch (InvalidCredentialInput) {
            $this->assertSame($before, $this->effects());
        }

        $before = $this->effects();
        $this->post(route('bfc.ui.installation-credentials.store'), [
            'app_purpose' => ['test.deploy'],
            'kind' => CredentialKind::Bearer->value,
            'subject_type' => SubjectType::Application->value,
            'subject_ref' => 'flags-off-malformed-purpose',
        ])->assertUnprocessable();
        $this->assertSame($before, $this->effects());

        $before = $this->effects();
        try {
            app(MintCredential::class)(
                new Subject(SubjectType::Installation, SigningRootMac::SUBJECT_REF),
                new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::SigningRoot),
            );
            $this->fail('Expected the reserved signing-root refusal.');
        } catch (CredentialVerbRefused) {
            $this->assertSame($before, $this->effects());
        }

        app()->instance('env', 'local');
        foreach ([
            fn (): TestResponse => $this->post(route('bfc.ui.installation-credentials.store'), [
                '_token' => 'invalid',
                'app_purpose' => 'test.deploy',
                'kind' => CredentialKind::Bearer->value,
                'subject_type' => SubjectType::Installation->value,
                'subject_ref' => 'flags-off-csrf',
            ]),
            fn (): TestResponse => $this->post(route('bfc.ui.installation-credentials.rotate', $manageable->id), ['_token' => 'invalid']),
            fn (): TestResponse => $this->delete(route('bfc.ui.installation-credentials.destroy', $manageable->id), ['_token' => 'invalid']),
        ] as $request) {
            $before = $this->effects();
            $request()->assertStatus(419)->assertDontSeeHtml('data-testid="installation-credentials-delivery"');
            $this->assertSame($before, $this->effects());
        }
    }

    /** @return array{Credential, string, TestResponse} */
    private function issue(
        User $actor,
        string $appPurpose,
        CredentialKind $kind,
        SubjectType $subjectType,
        string $name,
        string $subjectRef,
        bool $includeHostileFields = false,
    ): array {
        $this->actingAsVersioned($actor, 'web');
        $expiresAt = now()->addDay()->startOfSecond()->toAtomString();
        $payload = [
            'app_purpose' => $appPurpose,
            'kind' => $kind->value,
            'subject_type' => $subjectType->value,
            'subject_ref' => $subjectRef,
            'name' => $name,
            'expires_at' => $expiresAt,
            'code_ttl_seconds' => $kind === CredentialKind::Asymmetric ? 120 : null,
            SubmissionNonce::FIELD => $this->nonceFor(route('bfc.ui.installation-credentials.store')),
        ];

        if ($includeHostileFields) {
            $payload += [
                'purpose' => CredentialPurpose::SigningRoot->value,
                'abilities' => [OperatorAbility::Admin->value],
                'user_id' => 'hostile-user-id',
                'root' => SigningRootMac::SUBJECT_REF,
            ];
        }

        $delivery = $this->post(route('bfc.ui.installation-credentials.store'), $payload)
            ->assertStatus(201)
            ->assertSeeHtml('data-testid="installation-credentials-delivery"');
        $credential = Credential::query()->where('name', $name)->sole();

        return [$credential, $this->deliverySecret($delivery, $kind), $delivery];
    }

    private function prepareForUse(Credential $credential, TestResponse $delivery): void
    {
        if ($credential->kind === CredentialKind::Hmac) {
            preg_match('/<strong>delivery_fingerprint<\/strong>:\s*<code>([^<]+)<\/code>/', (string) $delivery->getContent(), $matches);
            $this->assertArrayHasKey(1, $matches);
            app(ActivateCredential::class)(
                $credential->id,
                html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5),
            );

            return;
        }

        if ($credential->kind === CredentialKind::Asymmetric) {
            $credential->forceFill([
                'status' => CredentialStatus::Active,
                'public_key' => CredentialFactory::generatePublicKey(),
            ])->save();
        }
    }

    private function assertCredentialUsable(Credential $credential, string $secret, bool $usable): void
    {
        if ($credential->kind === CredentialKind::Asymmetric) {
            if ($usable) {
                $this->assertSame(CredentialStatus::Active, $credential->refresh()->status);
                $this->assertNotNull($credential->public_key);
            } else {
                $this->assertNotNull($credential->refresh()->revoked_at);
            }

            return;
        }

        if ($credential->kind === CredentialKind::Hmac) {
            $response = $this->hmacRequest($credential, $secret);
        } else {
            $this->credentialAuthRoute();
            $header = $credential->kind === CredentialKind::Basic
                ? 'Basic '.base64_encode($credential->id.':'.$secret)
                : 'Bearer '.$secret;
            $response = $this->getJson('/p5-ui-e/credential-auth/'.$credential->purpose->value, [
                'Authorization' => $header,
            ]);
        }

        $usable
            ? $response->assertOk()->assertJsonPath('credential_id', $credential->id)
            : $response->assertUnauthorized();
    }

    private function credentialAuthRoute(): void
    {
        if (Route::getRoutes()->getByName('p5-ui-e.credential-auth') !== null) {
            return;
        }

        Route::get('/p5-ui-e/credential-auth/{purpose}', static function (string $purpose): array {
            $guard = Auth::guard('bfc');

            if (! $guard instanceof CredentialGuard) {
                abort(500);
            }

            $credential = $guard->credentialForPurposes([CredentialPurpose::from($purpose)]);

            if ($credential === null) {
                abort(401);
            }

            return ['credential_id' => $credential->id];
        })->name('p5-ui-e.credential-auth');
    }

    private function hmacRequest(Credential $credential, string $secret): TestResponse
    {
        if (Route::getRoutes()->getByName('p5-ui-e.hmac-auth') === null) {
            Route::post('/p5-ui-e/hmac-auth', static function (Request $request): array {
                return ['credential_id' => $request->attributes->get('bfc.hmac_credential_id')];
            })->middleware('bfc.hmac')->name('p5-ui-e.hmac-auth');
        }

        UiInstallationCredentialDeclaration::$hmacSubject = $credential->subject();
        $body = '{"test-created":"p5-ui-e"}';
        $envelope = new HmacEnvelope(
            keyId: $credential->id,
            eventType: 'p5-ui-e.test',
            timestamp: now()->getTimestamp(),
            nonce: bin2hex(random_bytes(16)),
            audience: (string) config('built-for-cloud.hmac.audience'),
        );

        return $this->call('POST', '/p5-ui-e/hmac-auth', server: [
            'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $envelope->headerValue(hash_hmac(
                'sha256',
                $envelope->canonical($body),
                $secret,
            )),
            'CONTENT_TYPE' => 'application/json',
        ], content: $body);
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

    private function assertImmediateReveal(TestResponse $response, string $secret): void
    {
        $this->assertSame(1, substr_count((string) $response->getContent(), $secret));
    }

    private function assertAuditActor(Credential $credential, LifecycleEventType $event, User $actor): void
    {
        $this->assertSame((string) $actor->getKey(), CredentialAuditEvent::query()
            ->where('credential_id', $credential->id)
            ->where('event', $event)
            ->value('actor_ref'));
    }

    private function user(UserRole|string $role): User
    {
        $roleValue = $role instanceof UserRole ? $role->value : $role;
        $user = User::query()->create([
            'name' => 'Test-created '.$roleValue,
            'email' => bin2hex(random_bytes(6)).'@example.test',
            'password' => bcrypt('test-created-password'),
        ]);
        $user->forceFill([
            'role' => $roleValue,
            'status' => 'active',
            'email_verified_at' => now(),
        ])->save();

        return $user;
    }

    /** @param list<string>|null $abilities */
    private function storedCredential(
        SubjectType $subjectType,
        string $name,
        ?string $userId = null,
        ?array $abilities = null,
    ): Credential {
        return Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'purpose' => $subjectType === SubjectType::UserPrincipal
                ? CredentialPurpose::Consumption
                : CredentialPurpose::SystemDeployment,
            'subject_type' => $subjectType,
            'subject_ref' => $name,
            'user_id' => $userId,
            'name' => $name,
            'abilities' => $abilities,
            'status' => CredentialStatus::Active,
            'secret_hash' => hash('sha256', 'secret-'.$name),
        ]);
    }

    private function signingRoot(): Credential
    {
        $encrypted = app(HmacKeyring::class)->encrypt(bin2hex(random_bytes(32)));
        $root = new Credential;
        $root->forceFill([
            'kind' => CredentialKind::Hmac,
            'purpose' => CredentialPurpose::SigningRoot,
            'subject_type' => SubjectType::Installation,
            'subject_ref' => SigningRootMac::SUBJECT_REF,
            'name' => 'excluded-signing-root',
            'status' => CredentialStatus::Active,
            'secret_ciphertext' => $encrypted->ciphertext,
            'secret_key_version' => $encrypted->keyVersion,
        ])->save();

        return $root;
    }

    /** @return array{credentials: int, audits: int, outbox: int, app_actions: int, app_action_outbox: int, tokens: int} */
    private function effectCounts(): array
    {
        return [
            'credentials' => Credential::query()->count(),
            'audits' => CredentialAuditEvent::query()->count(),
            'outbox' => CredentialOutboxEntry::query()->count(),
            'app_actions' => DB::table('bfc_app_action_events')->count(),
            'app_action_outbox' => DB::table('bfc_app_action_outbox')->count(),
            'tokens' => OnboardingToken::query()->count(),
        ];
    }

    /** @return array{counts: array<string, int>, rows: array<string, array<int, array<string, mixed>>>} */
    private function effects(): array
    {
        return [
            'counts' => $this->effectCounts(),
            'rows' => [
                'credentials' => Credential::query()->orderBy('id')->get()
                    ->map(static fn (Credential $credential): array => $credential->getRawOriginal())
                    ->all(),
                'audits' => CredentialAuditEvent::query()->orderBy('id')->get()
                    ->map(static fn (CredentialAuditEvent $event): array => $event->getRawOriginal())
                    ->all(),
                'outbox' => CredentialOutboxEntry::query()->orderBy('id')->get()
                    ->map(static fn (CredentialOutboxEntry $entry): array => $entry->getRawOriginal())
                    ->all(),
                'app_actions' => DB::table('bfc_app_action_events')->orderBy('id')->get()->map(fn ($row): array => (array) $row)->all(),
                'app_action_outbox' => DB::table('bfc_app_action_outbox')->orderBy('id')->get()->map(fn ($row): array => (array) $row)->all(),
                'tokens' => OnboardingToken::query()->orderBy('id')->get()
                    ->map(static fn (OnboardingToken $token): array => $token->getRawOriginal())
                    ->all(),
            ],
        ];
    }

    private function nonceFor(string $action): string
    {
        $page = $this->get(route('bfc.ui.installation-credentials.index'))->assertOk();
        $matched = preg_match(
            '/<form[^>]*action="'.preg_quote(htmlspecialchars($action, ENT_QUOTES), '/').'"[^>]*>.*?name="submission_nonce" value="([^"]+)"/s',
            (string) $page->getContent(),
            $matches,
        );
        $this->assertSame(1, $matched, 'The installation mutation form must carry a submission nonce.');

        $this->assertDatabaseHas('bfc_submission_nonces', [
            'nonce_hash' => hash('sha256', html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5)),
            'session_hash' => hash('sha256', $this->app['session']->getId()),
        ]);
        $this->withCookie((string) config('session.cookie'), $this->app['session']->getId());

        return html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5);
    }

    private function allFlagsOff(): void
    {
        config([
            'built-for-cloud.ui.landing_page' => false,
            'built-for-cloud.ui.member_management' => false,
            'built-for-cloud.ui.personal_credentials' => false,
            'built-for-cloud.ui.installation_credentials' => false,
            'built-for-cloud.ui.session_management' => false,
            'built-for-cloud.ui.managed_transitions' => false,
            'built-for-cloud.ui.credential_purposes' => [],
        ]);
    }
}
