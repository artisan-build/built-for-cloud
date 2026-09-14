<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\OwnerCredentialMinter;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class, WithCredentials::class);

function p5PurposeAllowed(CredentialKind $kind, SubjectType $subjectType, CredentialPurpose $purpose): bool
{
    return match ($kind) {
        CredentialKind::Hmac => $purpose === CredentialPurpose::Signing,
        CredentialKind::Asymmetric => $purpose === CredentialPurpose::Enrollment,
        CredentialKind::Bearer, CredentialKind::Basic => match ($subjectType) {
            SubjectType::Operator => in_array($purpose, [CredentialPurpose::OperatorManagement, CredentialPurpose::DashboardMetadata], true),
            SubjectType::Application, SubjectType::Installation => $purpose === CredentialPurpose::SystemDeployment,
            SubjectType::ExternalConsumer, SubjectType::UserPrincipal => in_array($purpose, [CredentialPurpose::Consumption, CredentialPurpose::Mcp], true),
        },
    };
}

it('defines exactly the eight protocol purposes', function (): void {
    expect(CredentialPurpose::values())->toBe([
        'operator_management',
        'dashboard_metadata',
        'consumption',
        'mcp',
        'signing',
        'signing_root',
        'enrollment',
        'system_deployment',
    ]);
});

it('admits every generic purpose matrix cell and refuses every other cell before effects', function (): void {
    foreach (CredentialKind::cases() as $kind) {
        foreach (SubjectType::cases() as $subjectType) {
            foreach (CredentialPurpose::cases() as $purpose) {
                $subject = new Subject($subjectType, 'matrix-'.bin2hex(random_bytes(8)));
                $before = [
                    Credential::query()->count(),
                    CredentialAuditEvent::query()->count(),
                    OnboardingToken::query()->count(),
                ];
                $options = new MintOptions(
                    kind: $kind,
                    purpose: $purpose,
                    codeTtlSeconds: $kind === CredentialKind::Asymmetric ? 600 : null,
                );

                if (p5PurposeAllowed($kind, $subjectType, $purpose)) {
                    $result = app(MintCredential::class)($subject, $options);
                    expect($result->summary->purpose)->toBe($purpose);

                    continue;
                }

                expect(fn () => app(MintCredential::class)($subject, $options))
                    ->toThrow(InvalidCredentialInput::class, 'not allowed');
                expect([
                    Credential::query()->count(),
                    CredentialAuditEvent::query()->count(),
                    OnboardingToken::query()->count(),
                ])->toBe($before);
            }
        }
    }
});

it('refuses missing unknown signing-root and reserved-pair purpose inputs before effects', function (): void {
    $before = [Credential::query()->count(), CredentialAuditEvent::query()->count(), OnboardingToken::query()->count()];

    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'missing-purpose'),
        new MintOptions,
    ))->toThrow(InvalidCredentialInput::class, 'purpose is required');
    expect(fn () => MintOptions::fromInput(['purpose' => 'unknown-purpose']))
        ->toThrow(InvalidCredentialInput::class, 'Unknown credential purpose');
    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Installation, 'ordinary'),
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::SigningRoot),
    ))->toThrow(InvalidCredentialInput::class, 'not allowed');
    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::Installation, CredentialPurpose::SIGNING_ROOT_SUBJECT_REF),
        new MintOptions(kind: CredentialKind::Hmac, purpose: CredentialPurpose::Signing),
    ))->toThrow(InvalidCredentialInput::class, 'not allowed');

    expect([Credential::query()->count(), CredentialAuditEvent::query()->count(), OnboardingToken::query()->count()])
        ->toBe($before);
});

it('reserves null purpose for tombstones that were already null when loaded', function (): void {
    $credential = Credential::factory()->revoked()->create();
    $credential->purpose = null;

    expect(fn () => $credential->save())
        ->toThrow(InvalidArgumentException::class, 'requires a known protocol purpose');
});

it('enforces every stored purpose tuple at the direct model boundary without effects', function (): void {
    foreach (CredentialKind::cases() as $kind) {
        foreach (SubjectType::cases() as $subjectType) {
            foreach (CredentialPurpose::cases() as $purpose) {
                $before = [
                    Credential::query()->count(),
                    CredentialAuditEvent::query()->count(),
                    CredentialOutboxEntry::query()->count(),
                    OnboardingToken::query()->count(),
                ];
                $store = static fn (): Credential => Credential::query()->create([
                    'kind' => $kind,
                    'purpose' => $purpose,
                    'subject_type' => $subjectType,
                    'subject_ref' => 'direct-model-'.bin2hex(random_bytes(8)),
                ]);
                $allowed = p5PurposeAllowed($kind, $subjectType, $purpose)
                    || ($kind === CredentialKind::Bearer
                        && $subjectType === SubjectType::ExternalConsumer
                        && $purpose === CredentialPurpose::Enrollment);

                if ($allowed) {
                    expect($store()->purpose)->toBe($purpose);

                    continue;
                }

                expect($store)->toThrow(InvalidArgumentException::class, 'valid for its kind and subject');
                expect([
                    Credential::query()->count(),
                    CredentialAuditEvent::query()->count(),
                    CredentialOutboxEntry::query()->count(),
                    OnboardingToken::query()->count(),
                ])->toBe($before);
            }
        }
    }
});

it('reserves the signing-root subject pair for its exact future stored shape', function (): void {
    foreach (CredentialKind::cases() as $kind) {
        foreach (CredentialPurpose::cases() as $purpose) {
            $before = Credential::query()->count();
            $store = static fn (): Credential => Credential::query()->create([
                'kind' => $kind,
                'purpose' => $purpose,
                'subject_type' => SubjectType::Installation,
                'subject_ref' => CredentialPurpose::SIGNING_ROOT_SUBJECT_REF,
            ]);

            if ($kind === CredentialKind::Hmac && $purpose === CredentialPurpose::SigningRoot) {
                expect($store()->purpose)->toBe(CredentialPurpose::SigningRoot);

                continue;
            }

            expect($store)->toThrow(InvalidArgumentException::class, 'valid for its kind and subject')
                ->and(Credential::query()->count())->toBe($before);
        }
    }
});

it('refuses every invalid raw rotation branch before mutation audit or delivery', function (): void {
    $invalid = [
        'bearer' => [CredentialKind::Bearer, SubjectType::Application, CredentialPurpose::Signing],
        'Basic' => [CredentialKind::Basic, SubjectType::Operator, CredentialPurpose::Signing],
        'HMAC' => [CredentialKind::Hmac, SubjectType::ExternalConsumer, CredentialPurpose::Consumption],
        'asymmetric' => [CredentialKind::Asymmetric, SubjectType::ExternalConsumer, CredentialPurpose::Signing],
    ];

    foreach ($invalid as $label => [$kind, $subjectType, $purpose]) {
        $id = (string) Str::uuid();
        $row = [
            'id' => $id,
            'kind' => $kind->value,
            'purpose' => $purpose->value,
            'subject_type' => $subjectType->value,
            'subject_ref' => 'invalid-rotation-'.strtolower($label),
            'name' => 'invalid '.$label,
            'abilities' => null,
            'status' => CredentialStatus::Active->value,
            'created_at' => now()->subMinute(),
            'updated_at' => now()->subMinute(),
        ];

        if (in_array($kind, [CredentialKind::Bearer, CredentialKind::Basic], true)) {
            $row['secret_hash'] = hash('sha256', 'invalid-'.$label);
        } elseif ($kind === CredentialKind::Hmac) {
            $encrypted = app(HmacKeyring::class)->encrypt('invalid-hmac-secret');
            $row['secret_ciphertext'] = $encrypted->ciphertext;
            $row['secret_key_version'] = $encrypted->keyVersion;
        } else {
            $row['public_key'] = CredentialFactory::generatePublicKey();
        }

        DB::table('credentials')->insert($row);
        $sourceBefore = (array) DB::table('credentials')->where('id', $id)->first();
        $countsBefore = [
            Credential::query()->count(),
            CredentialAuditEvent::query()->count(),
            CredentialOutboxEntry::query()->count(),
            OnboardingToken::query()->count(),
        ];
        $result = null;

        try {
            $result = app(RotateCredential::class)($id, new RotateOptions);
            test()->fail('The invalid '.$label.' source unexpectedly rotated.');
        } catch (InvalidArgumentException $exception) {
            expect($exception->getMessage())->toContain('valid for its kind and subject');
        }

        expect($result)->toBeNull()
            ->and((array) DB::table('credentials')->where('id', $id)->first())->toBe($sourceBefore)
            ->and([
                Credential::query()->count(),
                CredentialAuditEvent::query()->count(),
                CredentialOutboxEntry::query()->count(),
                OnboardingToken::query()->count(),
            ])->toBe($countsBefore);
    }
});

it('copies purpose through every ordinary rotation branch and exposes no override', function (CredentialKind $kind, CredentialPurpose $purpose): void {
    $source = match ($kind) {
        CredentialKind::Hmac => Credential::factory()->hmac()->activated()->create([
            'purpose' => $purpose,
            'subject_type' => SubjectType::ExternalConsumer,
        ]),
        CredentialKind::Asymmetric => Credential::factory()->asymmetric()->create([
            'purpose' => $purpose,
            'subject_type' => SubjectType::ExternalConsumer,
        ]),
        default => Credential::factory()->create([
            'kind' => $kind,
            'purpose' => $purpose,
            'subject_type' => SubjectType::ExternalConsumer,
        ]),
    };

    $rotation = app(RotateCredential::class)(
        $source->id,
        new RotateOptions(codeTtlSeconds: $kind === CredentialKind::Asymmetric ? 600 : null),
    );

    expect($rotation?->mint->summary->purpose)->toBe($purpose)
        ->and(Credential::query()->findOrFail($rotation?->mint->summary->id)->purpose)->toBe($purpose);
})->with([
    'bearer' => [CredentialKind::Bearer, CredentialPurpose::Consumption],
    'Basic' => [CredentialKind::Basic, CredentialPurpose::Consumption],
    'HMAC' => [CredentialKind::Hmac, CredentialPurpose::Signing],
    'asymmetric' => [CredentialKind::Asymmetric, CredentialPurpose::Enrollment],
]);

it('derives owner and installer bootstrap purpose and admin ability', function (): void {
    $owner = app(OwnerCredentialMinter::class)->mintFromHash(hash('sha256', 'owner-test-secret'));

    expect($owner->purpose)->toBe(CredentialPurpose::OperatorManagement)
        ->and($owner->abilities)->toBe([OperatorAbility::Admin->value]);

    expect(Artisan::call('bfc:install:operator-credential', ['--force' => true]))->toBe(0);
    $installed = Credential::query()->where('subject_ref', 'installer')->sole();

    expect($installed->purpose)->toBe(CredentialPurpose::OperatorManagement)
        ->and($installed->abilities)->toBe([OperatorAbility::Admin->value]);
});

it('exposes purpose in summary table and JSON listing without secret material', function (): void {
    $bearerSecret = 'list-bearer-'.bin2hex(random_bytes(12));
    $bearer = Credential::factory()->create([
        'purpose' => CredentialPurpose::SystemDeployment,
        'subject_ref' => 'list-purpose-row',
        'secret_hash' => hash('sha256', $bearerSecret),
    ]);
    $hmac = Credential::factory()->hmac('list-signing-key')->delivered()->create();
    $forbidden = array_filter([
        $bearer->secret_hash,
        $hmac->secret_ciphertext,
        $hmac->delivery_fingerprint,
        'list-signing-key',
    ]);

    expect(Artisan::call('bfc:credential:list', ['--local' => true]))->toBe(0);
    $table = Artisan::output();
    expect($table)->toContain($bearer->id, CredentialPurpose::SystemDeployment->value);

    expect(Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]))->toBe(0);
    $json = Artisan::output();
    $rows = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    $row = collect($rows)->firstWhere('id', $bearer->id);

    expect($row['purpose'])->toBe(CredentialPurpose::SystemDeployment->value);

    foreach ($forbidden as $material) {
        expect($table)->not->toContain($material)
            ->and($json)->not->toContain($material);
    }
});
