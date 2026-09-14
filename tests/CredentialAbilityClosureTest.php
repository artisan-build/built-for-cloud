<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesRotationOverrides;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\RotationOverride;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

it('closes the complete persisted ability vocabulary around the enum', function (): void {
    expect(OperatorAbility::tryFrom('credential:admin'))->toBe(OperatorAbility::Admin)
        ->and(OperatorAbility::vocabulary())->toBe(array_column(OperatorAbility::cases(), 'value'))
        ->and(OperatorAbility::vocabulary())->not->toContain('*', 'consume', 'onboard');

    expect(fn () => Credential::factory()->create(['abilities' => ['unknown:ability']]))
        ->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
});

it('refuses unknown abilities at action HTTP CLI and authorized rotation boundaries before writes', function (): void {
    $subject = new Subject(SubjectType::ExternalConsumer, 'unknown-ability');

    expect(fn () => app(MintCredential::class)(
        $subject,
        new MintOptions(
            purpose: CredentialPurpose::Consumption,
            abilities: ['unknown:action'],
        ),
    ))->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect(Credential::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0);

    $admin = $this->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::Admin->value],
    ]);
    $beforeHttp = Credential::query()->count();

    $this->postJson('/bfc/credentials', [
        'subject_type' => SubjectType::ExternalConsumer->value,
        'subject_ref' => 'unknown-http',
        'purpose' => CredentialPurpose::Consumption->value,
        'abilities' => ['unknown:http'],
    ], ['Authorization' => $admin->bearerHeader()])
        ->assertUnprocessable()
        ->assertJsonPath('message', 'Unknown credential ability "unknown:http".');
    expect(Credential::query()->count())->toBe($beforeHttp);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => SubjectType::ExternalConsumer->value,
        'subject-ref' => 'unknown-cli',
        '--purpose' => CredentialPurpose::Consumption->value,
        '--abilities' => 'unknown:cli',
        '--local' => true,
    ]))->toBe(1);
    expect(Credential::query()->count())->toBe($beforeHttp)
        ->and(Artisan::output())->toContain('Unknown credential ability');

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

    $source = Credential::factory()->create([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
    ]);
    $beforeRotate = Credential::query()->count();

    expect(fn () => app(RotateCredential::class)(
        $source->id,
        new RotateOptions(
            override: true,
            abilitiesProvided: true,
            abilities: ['unknown:rotation'],
        ),
    ))->toThrow(InvalidCredentialInput::class, 'Unknown credential ability');
    expect(Credential::query()->count())->toBe($beforeRotate)
        ->and($source->refresh()->rotated_at)->toBeNull();
});

it('enforces the exact admin-equivalent set without granting MCP or dashboard abilities', function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null],
        'built-for-cloud.credentials.guard' => 'bfc',
    ]);
    Auth::forgetGuards();

    $admin = $this->mintCredential([
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => SubjectType::Operator,
        'abilities' => [OperatorAbility::Admin->value],
    ]);

    foreach (OperatorAbility::adminEquivalent() as $ability) {
        $path = '/admin-equivalent/'.str_replace(':', '-', $ability->value);
        Route::middleware(EnsureCredentialAdmin::class.':'.$ability->value)
            ->get($path, fn () => response('ok'));

        $this->get($path, ['Authorization' => $admin->bearerHeader()])->assertOk();
    }

    Route::middleware(EnsureCredentialAdmin::class.':'.OperatorAbility::McpRead->value)
        ->get('/admin-not-mcp', fn () => response('ok'));
    Route::middleware(EnsureCredentialAdmin::class.':'.OperatorAbility::MetadataRead->value)
        ->get('/admin-not-metadata', fn () => response('ok'));
    Route::middleware(EnsureCredentialAbility::class.':'.OperatorAbility::McpAdmin->value)
        ->get('/exact-mcp-admin', fn () => response('ok'));
    Route::middleware(EnsureDashboardCredential::class)
        ->get('/exact-dashboard', fn () => response('ok'));

    $this->get('/admin-not-mcp', ['Authorization' => $admin->bearerHeader()])->assertForbidden();
    $this->get('/admin-not-metadata', ['Authorization' => $admin->bearerHeader()])->assertForbidden();
    $this->get('/exact-mcp-admin', ['Authorization' => $admin->bearerHeader()])->assertForbidden();
    $this->get('/exact-dashboard', ['Authorization' => $admin->bearerHeader()])->assertForbidden();
});
