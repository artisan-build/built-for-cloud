<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('validates every bound string and the shared audience grammar', function (array $change): void {
    $values = [
        'appPurpose' => 'reel.application.signing',
        'subjectRef' => 'subject-1',
        'installation' => 'install-1',
        'application' => 'app-1',
        'audience' => 'https://reel.example',
    ];
    $values = array_merge($values, $change);

    expect(fn () => new BoundCredentialScope(
        $values['appPurpose'],
        new Subject(SubjectType::Installation, $values['subjectRef']),
        $values['installation'],
        $values['application'],
        $values['audience'],
    ))->toThrow(InvalidCredentialInput::class, 'bound credential scope is invalid');
})->with([
    'empty' => [['installation' => '']],
    'control' => [['application' => "app\n1"]],
    'invalid utf8' => [['subjectRef' => "bad\xFF"]],
    'over 255 bytes' => [['appPurpose' => str_repeat('a', 256)]],
    'audience whitespace' => [['audience' => 'https://reel.example/a b']],
    'audience comma' => [['audience' => 'reel,matte']],
]);

it('mints only fully mapped bound signing credentials and freezes the hash encoding', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );
    $binding = CredentialProtocolBinding::query()->findOrFail($mint->summary->id);

    expect($binding->app_purpose)->toBe($scope->appPurpose)
        ->and($binding->installation_ref)->toBe($scope->installation)
        ->and($binding->application_ref)->toBe($scope->application)
        ->and($binding->audience)->toBe($scope->audience)
        ->and($binding->algorithm)->toBe(CredentialAlgorithm::Rs256)
        ->and($binding->material_role)->toBe(CredentialMaterialRole::Originator)
        ->and($binding->scope_hash)->toBe(CredentialProtocolBinding::scopeHash(
            $scope,
            CredentialPurpose::Signing,
            CredentialAlgorithm::Rs256,
            CredentialMaterialRole::Originator,
        ))
        ->and($binding->scope_hash)->toBe('fa5bf2540a6a786d972ba5dc0e2d40744abd3543e62e710c98ef4f55c5114676');
});

it('admits the M1 mapping foundation without changing generic purpose admission', function (): void {
    testsConfigureBoundPurposes();
    $scope = new BoundCredentialScope(
        'matte.callback',
        new Subject(SubjectType::ExternalConsumer, 'matte-originator'),
        'matte-install',
        'matte-app',
        'https://matte.example',
    );
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::Signing, boundScope: $scope),
    );

    expect(CredentialProtocolBinding::query()->findOrFail($mint->summary->id)->algorithm)
        ->toBe(CredentialAlgorithm::HmacSha256)
        ->and(CredentialPurpose::Signing->allowedFor(CredentialKind::Asymmetric, SubjectType::Installation))
        ->toBeFalse();
});

it('refuses unbound signing asymmetric and every bound authority mismatch without effects', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $cases = [
        new MintOptions(kind: CredentialKind::Asymmetric, purpose: CredentialPurpose::Signing, codeTtlSeconds: 3600),
        new MintOptions(kind: CredentialKind::Bearer, purpose: CredentialPurpose::Signing, boundScope: $scope),
        new MintOptions(kind: CredentialKind::Asymmetric, purpose: CredentialPurpose::Enrollment, codeTtlSeconds: 3600, boundScope: $scope),
        new MintOptions(kind: CredentialKind::Asymmetric, purpose: CredentialPurpose::Signing, userId: 'user-1', codeTtlSeconds: 3600, boundScope: $scope),
    ];

    foreach ($cases as $options) {
        expect(fn () => app(MintCredential::class)($scope->subject, $options))->toThrow(InvalidCredentialInput::class);
    }

    expect(Credential::query()->count())->toBe(0)
        ->and(CredentialProtocolBinding::query()->count())->toBe(0);
});

it('re-resolves mappings at use regardless of every UI flag combination or a preconstructed scope', function (): void {
    $scope = testsBoundScope();

    foreach ([[false, false], [false, true], [true, false], [true, true]] as [$personal, $installation]) {
        config([
            'built-for-cloud.credentials.app_purposes' => ['reel.application.signing' => 'signing'],
            'built-for-cloud.ui.personal_credentials' => $personal,
            'built-for-cloud.ui.installation_credentials' => $installation,
        ]);

        app(MintCredential::class)(
            $scope->subject,
            new MintOptions(
                kind: CredentialKind::Asymmetric,
                purpose: CredentialPurpose::Signing,
                codeTtlSeconds: 3600,
                boundScope: $scope,
            ),
        );
    }

    foreach ([
        null,
        [],
        ['reel.application.signing' => ['signing']],
        ['reel.application.signing' => 1],
        ['reel.application.signing' => 'unknown'],
    ] as $mappings) {
        config(['built-for-cloud.credentials.app_purposes' => $mappings]);

        expect(fn () => app(MintCredential::class)(
            $scope->subject,
            new MintOptions(
                kind: CredentialKind::Asymmetric,
                purpose: CredentialPurpose::Signing,
                codeTtlSeconds: 3600,
                boundScope: $scope,
            ),
        ))->toThrow(InvalidCredentialInput::class, 'app purpose mapping is invalid');
    }

    $malformed = new BoundCredentialScope(
        'not-a-mapping-id',
        $scope->subject,
        $scope->installation,
        $scope->application,
        $scope->audience,
    );
    config(['built-for-cloud.credentials.app_purposes' => ['not-a-mapping-id' => 'signing']]);
    expect(fn () => app(MintCredential::class)(
        $malformed->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $malformed,
        ),
    ))->toThrow(InvalidCredentialInput::class, 'app purpose mapping is invalid');

    expect(Credential::query()->count())->toBe(4);
});

it('round trips enum bindings and enforces one binding per credential', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );
    $binding = CredentialProtocolBinding::query()->findOrFail($mint->summary->id);

    expect($binding->algorithm)->toBe(CredentialAlgorithm::Rs256)
        ->and($binding->material_role)->toBe(CredentialMaterialRole::Originator);

    expect(fn () => DB::table('credential_protocol_bindings')->insert([
        'credential_id' => $mint->summary->id,
        'app_purpose' => $scope->appPurpose,
        'installation_ref' => $scope->installation,
        'application_ref' => $scope->application,
        'audience' => $scope->audience,
        'algorithm' => CredentialAlgorithm::Rs256->value,
        'material_role' => CredentialMaterialRole::Originator->value,
        'scope_hash' => $binding->scope_hash,
        'created_at' => now(),
        'updated_at' => now(),
    ]))->toThrow(QueryException::class);
});

it('copies an exact binding through rotation and refuses verification-copy rotation', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );
    $source = Credential::query()->findOrFail($mint->summary->id);
    DB::table('credentials')->where('id', $source->id)->update([
        'status' => 'active',
        'public_key' => testsRsaKey()['public'],
        'activated_at' => now(),
    ]);
    $rotation = app(RotateCredential::class)($source->id, new RotateOptions(codeTtlSeconds: 3600));
    $replacement = CredentialProtocolBinding::query()->findOrFail($rotation?->mint->summary->id);
    $original = CredentialProtocolBinding::query()->findOrFail($source->id);

    expect($replacement->only([
        'app_purpose', 'installation_ref', 'application_ref', 'audience', 'algorithm', 'material_role', 'scope_hash',
    ]))->toBe($original->only([
        'app_purpose', 'installation_ref', 'application_ref', 'audience', 'algorithm', 'material_role', 'scope_hash',
    ]));

    DB::table('credential_protocol_bindings')->where('credential_id', $source->id)->update([
        'material_role' => CredentialMaterialRole::VerificationCopy->value,
        'scope_hash' => CredentialProtocolBinding::scopeHash(
            $scope,
            CredentialPurpose::Signing,
            CredentialAlgorithm::Rs256,
            CredentialMaterialRole::VerificationCopy,
        ),
    ]);

    expect(fn () => app(RotateCredential::class)($source->id, new RotateOptions))
        ->toThrow(RotationRefused::class, 'verification copy');
});
