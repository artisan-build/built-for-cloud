<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\ActivationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class, WithCredentials::class);

it('stores and bounds the closed purpose and ability vocabularies', function (): void {
    expect(Schema::hasColumn('credentials', 'purpose'))->toBeTrue()
        ->and(array_column(CredentialPurpose::cases(), 'value'))->toBe([
            'operator_management',
            'dashboard_metadata',
            'consumption',
            'mcp',
            'signing',
            'signing_root',
            'enrollment',
            'system_deployment',
        ])
        ->and(OperatorAbility::tryFrom('credential:admin'))->toBe(OperatorAbility::Admin);

    expect(fn () => MintOptions::fromInput(['abilities' => ['invented:grant']]))
        ->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');

    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Application, 'app'),
        new MintOptions(kind: CredentialKind::Bearer),
    ))->toThrow(InvalidCredentialInput::class, 'purpose is required');

    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Operator, 'ops'),
        new MintOptions(kind: CredentialKind::Bearer, purpose: CredentialPurpose::Consumption),
    ))->toThrow(InvalidCredentialInput::class, 'not allowed');

    $mint = app(MintCredential::class)(
        new Subject(SubjectType::Application, 'deploy'),
        new MintOptions(kind: CredentialKind::Bearer, purpose: CredentialPurpose::SystemDeployment),
    );

    $rotation = app(RotateCredential::class)($mint->summary->id, new RotateOptions);

    expect($mint->summary->purpose)->toBe(CredentialPurpose::SystemDeployment)
        ->and($rotation?->mint->summary->purpose)->toBe(CredentialPurpose::SystemDeployment);
});

it('maps claim scopes to purpose ability and subject without magic abilities', function (): void {
    $minter = app(UnifiedStoreCredentialMinter::class);

    $consume = $minter->mint('consumer', Scope::Consume->value)->token;
    $admin = $minter->mint('administrator', Scope::Admin->value)->token;
    $onboard = $minter->mint('enrollee', Scope::Onboard->value)->token;

    expect([$consume->purpose, $consume->subject_type, $consume->abilities])
        ->toBe([CredentialPurpose::Consumption, SubjectType::ExternalConsumer, []])
        ->and([$admin->purpose, $admin->subject_type, $admin->abilities])
        ->toBe([CredentialPurpose::OperatorManagement, SubjectType::Operator, [OperatorAbility::Admin->value]])
        ->and([$onboard->purpose, $onboard->subject_type, $onboard->abilities])
        ->toBe([CredentialPurpose::Enrollment, SubjectType::ExternalConsumer, []]);

    expect(fn () => $minter->mint('unknown', 'unknown'))
        ->toThrow(InvalidCredentialInput::class, 'Unknown claim scope');
});

it('rechecks cached credentials for each stacked purpose gate', function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null],
        'built-for-cloud.credentials.guard' => 'bfc',
    ]);
    Auth::forgetGuards();

    Route::middleware(['auth:bfc', 'bfc.ability:'.OperatorAbility::McpRead->value])
        ->get('/purpose-stacked', fn () => response('ok'));
    Route::middleware('bfc.ability:'.OperatorAbility::McpRead->value)
        ->get('/purpose-ability-only', fn () => response('ok'));

    $consumption = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);
    $deployment = $this->mintCredential([
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_type' => SubjectType::Application,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);
    $mcp = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => [OperatorAbility::McpRead->value],
    ]);

    $this->withHeader('Authorization', $consumption->bearerHeader())->get('/purpose-stacked')->assertOk();
    $this->withHeader('Authorization', $deployment->bearerHeader())->get('/purpose-stacked')->assertUnauthorized();
    $this->withHeader('Authorization', $mcp->bearerHeader())->get('/purpose-ability-only')->assertOk();

    /** @var CredentialGuard $guard */
    $guard = Auth::guard('bfc');
    expect($guard->validate(['secret' => $mcp->plaintext()]))->toBeFalse()
        ->and($guard->validate(['secret' => $consumption->plaintext()]))->toBeTrue();
});

it('maps app purposes independently of ui affordances', function (): void {
    config([
        'built-for-cloud.credentials.app_purposes' => ['hone.ingest' => CredentialPurpose::Consumption->value],
        'built-for-cloud.ui.personal_credentials' => false,
    ]);

    expect(app(AppPurposeRegistry::class)->protocolPurpose('hone.ingest'))
        ->toBe(CredentialPurpose::Consumption);

    config(['built-for-cloud.ui.personal_credentials' => true]);

    expect(app(AppPurposeRegistry::class)->protocolPurpose('hone.ingest'))
        ->toBe(CredentialPurpose::Consumption)
        ->and(fn () => app(AppPurposeRegistry::class)->protocolPurpose('unmapped.value'))
        ->toThrow(InvalidCredentialInput::class, 'Unknown or unmapped app purpose');
});

it('checks purpose before dashboard admin and mcp authority effects', function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null],
        'built-for-cloud.credentials.guard' => 'bfc',
    ]);
    Auth::forgetGuards();

    Route::middleware(EnsureDashboardCredential::class)
        ->get('/purpose-dashboard', fn () => response('ok'));
    Route::middleware(EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value)
        ->get('/purpose-admin', fn () => response('ok'));
    Route::middleware(AuthenticateMcp::class)
        ->get('/purpose-mcp', fn () => response()->json([
            'credential_id' => request()->user()?->getAuthIdentifier(),
            'actor_id' => request()->attributes->get('bfc.actor_credential_id'),
        ]));

    $dashboard = $this->mintCredential([
        'purpose' => CredentialPurpose::DashboardMetadata,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::MetadataRead->value],
    ]);
    $admin = $this->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::Admin->value],
    ]);
    $wrongAdminPurpose = $this->mintCredential([
        'purpose' => CredentialPurpose::DashboardMetadata,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::Admin->value],
    ]);
    $mcp = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
    ]);
    $wrongMcpPurpose = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
    ]);

    $this->withHeader('Authorization', $dashboard->bearerHeader())->get('/purpose-dashboard')->assertOk();
    $this->withHeader('Authorization', $admin->bearerHeader())->get('/purpose-admin')->assertOk();
    $this->withHeader('Authorization', $wrongAdminPurpose->bearerHeader())->get('/purpose-admin')->assertUnauthorized();
    expect($wrongAdminPurpose->credential->refresh()->last_used_at)->toBeNull();

    $this->withHeader('Authorization', $mcp->bearerHeader())
        ->get('/purpose-mcp')
        ->assertOk()
        ->assertJsonPath('credential_id', $mcp->credential->id)
        ->assertJsonPath('actor_id', null);
    $this->withHeader('Authorization', $admin->bearerHeader())
        ->get('/purpose-mcp')
        ->assertOk()
        ->assertJsonPath('actor_id', $admin->credential->id);
    $this->withHeader('Authorization', $wrongMcpPurpose->bearerHeader())->get('/purpose-mcp')->assertUnauthorized();
    expect($wrongMcpPurpose->credential->refresh()->last_used_at)->toBeNull();
});

it('provisions macs verifies rotates and reserves the non-exported signing root', function (): void {
    $provisioned = app(SigningRootLifecycle::class)->provision();
    $root = Credential::query()->findOrFail($provisioned->summary->id);

    expect($provisioned->delivery)->toBe(DeliveryShape::None)
        ->and($provisioned->secret)->toBeNull()
        ->and($root->purpose)->toBe(CredentialPurpose::SigningRoot)
        ->and($root->status)->toBe(CredentialStatus::Active)
        ->and($root->delivered_at)->toBeNull()
        ->and($root->delivery_fingerprint)->toBeNull();

    $old = app(SigningRootMac::class)->mac("canonical\0bytes");
    expect($old->keyId)->toBe($root->id)
        ->and($old->mac)->toMatch('/^[a-f0-9]{64}$/')
        ->and(app(SigningRootMac::class)->verify($old->keyId, "canonical\0bytes", $old->mac))->toBeTrue()
        ->and(app(SigningRootMac::class)->verify($old->keyId, 'changed', $old->mac))->toBeFalse();

    $rotation = app(RotateCredential::class)($root->id, new RotateOptions);
    $new = app(SigningRootMac::class)->mac('new bytes');

    expect($rotation?->mint->delivery)->toBe(DeliveryShape::None)
        ->and($new->keyId)->not->toBe($old->keyId)
        ->and(app(SigningRootMac::class)->verify($old->keyId, "canonical\0bytes", $old->mac))->toBeTrue();

    expect(fn () => app(ActivateCredential::class)($new->keyId, 'not-a-delivery'))
        ->toThrow(ActivationRefused::class, 'signing root');
    expect(fn () => app(OffboardSubject::class)(OffboardOptions::fromInput([
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => SigningRootMac::SUBJECT_REF,
    ])))->toThrow(InvalidCredentialInput::class, 'dedicated lifecycle');
    expect(fn () => app(RevokeCredential::class)($new->keyId))
        ->toThrow(InvalidCredentialInput::class, 'dedicated lifecycle');
    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Installation, SigningRootMac::SUBJECT_REF),
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::Signing),
    ))->toThrow(InvalidCredentialInput::class, 'not allowed');
    expect(fn () => app(HmacSigner::class)->sign(
        new Subject(SubjectType::Installation, SigningRootMac::SUBJECT_REF),
        'body',
        'event',
    ))->toThrow(HmacSigningRefused::class);
});

it('exposes one local-only root provisioning command without material delivery', function (): void {
    $this->artisan('bfc:signing-root:provision', ['--local' => true])
        ->assertSuccessful();

    $root = Credential::query()->where('purpose', CredentialPurpose::SigningRoot->value)->sole();

    expect($root->secret_ciphertext)->not->toBeNull()
        ->and($root->delivered_at)->toBeNull()
        ->and($root->delivery_fingerprint)->toBeNull();
});
