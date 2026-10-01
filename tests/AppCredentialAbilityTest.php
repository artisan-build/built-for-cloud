<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesRotationOverrides;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAbilityRegistry;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\RotationOverride;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\CredentialAbilityAssertions;
use ArtisanBuild\BuiltForCloud\Testing\FakeCredentialAbilityRegistry;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\AppCredentialAbilityServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class, WithCredentials::class);

function allowAppAbilityRotationOverrides(): void
{
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
}

function configureAppAbilityGuard(): void
{
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null],
        'built-for-cloud.credentials.guard' => 'bfc',
    ]);
    Auth::forgetGuards();
}

it('binds an empty registry and supports registration from an application service provider', function (): void {
    $registry = app(CredentialAbilityRegistry::class);

    expect($registry->all())->toBe([]);

    app()->register(AppCredentialAbilityServiceProvider::class);

    expect($registry->all())->toBe(['assay.usage', 'assay.content'])
        ->and($registry->has('assay.usage'))->toBeTrue()
        ->and($registry->has('assay.content'))->toBeTrue();
});

it('validates registrations atomically and treats duplicate registration as idempotent', function (): void {
    $registry = app(CredentialAbilityRegistry::class);
    $registry->register('a.b', 'assay-2.content_v1.read-only');
    $registry->register('a.b');

    expect($registry->all())->toBe(['a.b', 'assay-2.content_v1.read-only']);

    foreach ([
        'assay',
        'Assay.usage',
        'assay:usage',
        '1assay.usage',
        '.usage',
        'assay.',
        'assay..usage',
        'assay.usage.',
    ] as $malformed) {
        expect(fn () => $registry->register($malformed))
            ->toThrow(InvalidArgumentException::class, 'Invalid app credential ability');
    }

    expect(fn () => $registry->register(OperatorAbility::CredentialRead->value))
        ->toThrow(InvalidArgumentException::class, 'collides with the OperatorAbility vocabulary');

    $before = $registry->all();

    expect(fn () => $registry->register('assay.valid', 'assay..invalid'))
        ->toThrow(InvalidArgumentException::class);
    expect($registry->all())->toBe($before);
});

it('accepts registered abilities through model saves and minting and rejects unregistered values before writes', function (): void {
    $registry = FakeCredentialAbilityRegistry::install(app());
    $registry->register('assay.usage', 'assay.content');

    $direct = Credential::factory()->create(['abilities' => ['assay.usage']]);
    $direct->abilities = ['assay.content'];
    $direct->save();

    expect($direct->refresh()->abilities)->toBe(['assay.content']);

    $mint = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'assay-consumer'),
        new MintOptions(
            purpose: CredentialPurpose::Consumption,
            abilities: ['assay.usage'],
        ),
    );

    expect($mint->summary->abilities)->toBe(['assay.usage']);

    $credentialCount = Credential::query()->count();
    $auditCount = CredentialAuditEvent::query()->count();

    expect(fn () => Credential::factory()->create(['abilities' => ['assay.unregistered']]))
        ->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect(Credential::query()->count())->toBe($credentialCount)
        ->and(CredentialAuditEvent::query()->count())->toBe($auditCount);

    $direct->abilities = ['assay.unregistered'];

    expect(fn () => $direct->save())
        ->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect($direct->refresh()->abilities)->toBe(['assay.content'])
        ->and(Credential::query()->count())->toBe($credentialCount)
        ->and(CredentialAuditEvent::query()->count())->toBe($auditCount);

    expect(fn () => app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'unregistered-consumer'),
        new MintOptions(
            purpose: CredentialPurpose::Consumption,
            abilities: ['assay.unregistered'],
        ),
    ))->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect(Credential::query()->count())->toBe($credentialCount)
        ->and(CredentialAuditEvent::query()->count())->toBe($auditCount);
});

it('preserves registered abilities on routine rotation and accepts registered explicit overrides', function (): void {
    $registry = FakeCredentialAbilityRegistry::install(app());
    $registry->register('assay.usage', 'assay.content');
    allowAppAbilityRotationOverrides();

    $routineSource = Credential::factory()->create(['abilities' => ['assay.usage']]);
    $routine = app(RotateCredential::class)($routineSource->id, new RotateOptions);

    expect($routine)->not->toBeNull()
        ->and($routine?->mint->summary->abilities)->toBe(['assay.usage'])
        ->and(Credential::query()->findOrFail($routine?->mint->summary->id)->abilities)->toBe(['assay.usage']);

    $overrideSource = Credential::factory()->create(['abilities' => ['assay.usage']]);
    $override = app(RotateCredential::class)(
        $overrideSource->id,
        new RotateOptions(
            override: true,
            abilitiesProvided: true,
            abilities: ['assay.content'],
        ),
    );

    expect($override)->not->toBeNull()
        ->and($override?->mint->summary->abilities)->toBe(['assay.content']);

    $refusedSource = Credential::factory()->create(['abilities' => ['assay.usage']]);
    $credentialCount = Credential::query()->count();
    $auditCount = CredentialAuditEvent::query()->count();

    expect(fn () => app(RotateCredential::class)(
        $refusedSource->id,
        new RotateOptions(
            override: true,
            abilitiesProvided: true,
            abilities: ['assay.unregistered'],
        ),
    ))->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect(Credential::query()->count())->toBe($credentialCount)
        ->and(CredentialAuditEvent::query()->count())->toBe($auditCount)
        ->and($refusedSource->refresh()->rotated_at)->toBeNull();
});

it('matches an app ability exactly and never grants operator or wildcard-like names', function (): void {
    $registry = FakeCredentialAbilityRegistry::install(app());
    $registry->register('assay.usage', 'assay.content');
    configureAppAbilityGuard();

    $credential = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => ['assay.usage'],
    ]);

    foreach (['assay.usage', 'assay', 'assay.*', 'assay.content', OperatorAbility::CredentialRead->value] as $ability) {
        Route::middleware('bfc.ability:'.$ability)
            ->get('/app-ability/'.str_replace(['.', ':', '*'], '-', $ability), static fn (): array => ['ok' => true]);
    }

    $headers = ['Authorization' => $credential->bearerHeader()];

    $this->get('/app-ability/assay-usage', $headers)->assertOk();
    $this->get('/app-ability/assay', $headers)->assertForbidden();
    $this->get('/app-ability/assay--', $headers)->assertForbidden();
    $this->get('/app-ability/assay-content', $headers)->assertForbidden();
    $this->get('/app-ability/credential-read', $headers)->assertForbidden();

    expect($credential->credential->hasAbility('assay.usage'))->toBeTrue()
        ->and($credential->credential->hasAbility('assay'))->toBeFalse()
        ->and($credential->credential->hasAbility('assay.*'))->toBeFalse()
        ->and($credential->credential->hasAbility('assay.content'))->toBeFalse()
        ->and($credential->credential->hasAbility(OperatorAbility::CredentialRead->value))->toBeFalse();
});

it('keeps historical rows readable but stops matching an ability after registration removal', function (): void {
    $registry = FakeCredentialAbilityRegistry::install(app());
    $registry->register('assay.usage');
    configureAppAbilityGuard();

    $credential = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'abilities' => ['assay.usage'],
    ]);
    Route::middleware('bfc.ability:assay.usage')
        ->get('/removed-app-ability', static fn (): array => ['ok' => true]);

    $registry->reset();

    $historical = Credential::query()->findOrFail($credential->credential->id);

    expect($historical->getRawOriginal('abilities'))->toBe('["assay.usage"]')
        ->and($historical->abilities)->toBe(['assay.usage'])
        ->and($historical->hasAbility('assay.usage'))->toBeFalse();

    $this->get('/removed-app-ability', ['Authorization' => $credential->bearerHeader()])
        ->assertForbidden();
});

it('ships a fake registry and a loud registration assertion for consuming tests', function (): void {
    $registry = FakeCredentialAbilityRegistry::install(app());
    $registry->register('assay.usage');

    CredentialAbilityAssertions::assertRegistered(app(), 'assay.usage');

    expect(fn () => CredentialAbilityAssertions::assertRegistered(app(), 'assay.content'))
        ->toThrow(AssertionFailedError::class, 'Credential ability [assay.content] is not registered.');
});
