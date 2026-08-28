<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\DefaultCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

beforeEach(function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
    ]);

    Route::middleware('auth:bfc')->get('/bfc-guarded', fn (): array => ['ok' => true]);

    Route::middleware(['auth:bfc', 'bfc.ability:credential:read'])->get('/needs-read', fn (): array => ['ok' => true]);
    Route::middleware(['auth:bfc', 'bfc.ability:credential:revoke'])->get('/needs-revoke', fn (): array => ['ok' => true]);
    Route::middleware(['auth:bfc', 'bfc.ability:'])->get('/misconfigured-ability', fn (): array => ['ok' => true]);
});

it('fails closed: null abilities grant nothing', function (): void {
    $minted = $this->mintCredential(['abilities' => null]);

    $this->getJson('/needs-read', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(403);
});

it('fails closed: empty abilities grant nothing', function (): void {
    $minted = $this->mintCredential(['abilities' => []]);

    $this->getJson('/needs-read', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(403);
});

it('passes a held ability and fails a missing one', function (): void {
    $minted = $this->mintCredential(['abilities' => ['credential:read']]);

    $this->getJson('/needs-read', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200);

    $this->getJson('/needs-revoke', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(403);
});

it('requires an explicit ability string on the middleware', function (): void {
    $minted = $this->mintCredential(['abilities' => ['credential:read']]);

    $this->withoutExceptionHandling();

    expect(fn () => $this->getJson('/misconfigured-ability', ['Authorization' => $minted->bearerHeader()]))
        ->toThrow(InvalidArgumentException::class);
});

it('returns 401 from the abilities middleware without a credential', function (): void {
    Route::middleware('bfc.ability:credential:read')->get('/ability-only', fn (): array => ['ok' => true]);

    $this->getJson('/ability-only')->assertStatus(401);
});

it('produces 403 when a declaration denies an otherwise-valid credential', function (): void {
    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class implements CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return false;
        }
    });

    $minted = $this->mintCredential(['abilities' => ['credential:read']]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(403);
});

it('feeds subject_ref to the declaration as an input, never as the check itself', function (): void {
    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class implements CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return $credential->subject_ref === 'tenant-a';
        }
    });

    $allowed = $this->mintCredential(['subject_ref' => 'tenant-a']);
    $denied = $this->mintCredential(['subject_ref' => 'tenant-b']);

    $this->getJson('/bfc-guarded', ['Authorization' => $allowed->bearerHeader()])
        ->assertStatus(200);

    $this->getJson('/bfc-guarded', ['Authorization' => $denied->bearerHeader()])
        ->assertStatus(403);
});

it('consults the declaration with the required ability on ability routes', function (): void {
    $seen = new ArrayObject;

    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class($seen) implements CredentialDeclaration
    {
        public function __construct(private readonly ArrayObject $seen) {}

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            $this->seen->append($ability);

            return true;
        }
    });

    $minted = $this->mintCredential(['abilities' => ['credential:read']]);

    $this->getJson('/needs-read', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200);

    expect($seen->getArrayCopy())->toContain(null)
        ->and($seen->getArrayCopy())->toContain('credential:read');
});

it('ships a default declaration that works out of the box', function (): void {
    $declaration = app(CredentialDeclaration::class);

    expect($declaration)->toBeInstanceOf(DefaultCredentialDeclaration::class)
        ->and($declaration->resolveSubject(Request::create('/anything')))->toBeNull();

    $minted = $this->mintCredential();

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200);
});

it('registers a declaration class through config', function (): void {
    config(['built-for-cloud.credentials.declaration' => DefaultCredentialDeclaration::class]);

    expect(app(CredentialDeclaration::class))->toBeInstanceOf(DefaultCredentialDeclaration::class);
});
