<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

beforeEach(function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
    ]);

    Route::middleware('auth:bfc')->get('/bfc-guarded', fn (): array => [
        'ok' => true,
        'principal' => auth('bfc')->id(),
    ]);
});

it('authenticates a bearer credential and stamps last_used_at', function (): void {
    $minted = $this->mintCredential();

    expect($minted->credential->last_used_at)->toBeNull();

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('principal', $minted->credential->id);

    expect($minted->credential->refresh()->last_used_at)->not->toBeNull();
});

it('authenticates an http basic credential in the auth.json shape', function (): void {
    $minted = $this->mintCredential([
        'kind' => CredentialKind::Basic,
        'purpose' => CredentialPurpose::SystemDeployment,
    ]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->basicHeader('any-username')])
        ->assertOk()
        ->assertJsonPath('principal', $minted->credential->id);

    expect($minted->credential->refresh()->last_used_at)->not->toBeNull();
});

it('does not authenticate a bearer presentation against a basic credential or vice versa', function (): void {
    $basic = $this->mintCredential([
        'kind' => CredentialKind::Basic,
        'purpose' => CredentialPurpose::SystemDeployment,
    ]);
    $bearer = $this->mintCredential();

    $this->getJson('/bfc-guarded', ['Authorization' => $basic->bearerHeader()])
        ->assertUnauthorized();

    $this->getJson('/bfc-guarded', ['Authorization' => $bearer->basicHeader()])
        ->assertUnauthorized();
});

it('rejects a revoked credential', function (): void {
    $minted = $this->mintCredential(['revoked_at' => now()]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertUnauthorized();

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('rejects an expired credential', function (): void {
    $minted = $this->mintCredential(['expires_at' => now()->subMinute()]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertUnauthorized();

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('rejects a pending credential', function (): void {
    $minted = $this->mintCredential(['status' => 'pending']);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertUnauthorized();

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('rejects an unknown secret and a malformed header', function (): void {
    $this->getJson('/bfc-guarded', ['Authorization' => 'Bearer nope'])->assertUnauthorized();
    $this->getJson('/bfc-guarded', ['Authorization' => 'Bearer'])->assertUnauthorized();
    $this->getJson('/bfc-guarded', ['Authorization' => 'Basic not-base64!!'])->assertUnauthorized();
    $this->getJson('/bfc-guarded', ['Authorization' => 'Basic '.base64_encode('no-colon')])->assertUnauthorized();
    $this->getJson('/bfc-guarded', ['Authorization' => 'Digest whatever'])->assertUnauthorized();
    $this->getJson('/bfc-guarded')->assertUnauthorized();
});

it('does not distinguish a revoked credential from an unknown one', function (): void {
    $revoked = $this->mintCredential(['revoked_at' => now()]);

    $revokedResponse = $this->getJson('/bfc-guarded', ['Authorization' => $revoked->bearerHeader()]);
    $unknownResponse = $this->getJson('/bfc-guarded', ['Authorization' => 'Bearer '.bin2hex(random_bytes(32))]);

    expect($revokedResponse->getStatusCode())->toBe($unknownResponse->getStatusCode())
        ->and($revokedResponse->getContent())->toBe($unknownResponse->getContent());
});

it('resolves the bound user as the principal for a user-bound credential', function (): void {
    $user = User::query()->create([
        'name' => 'Priya',
        'email' => 'priya@example.com',
        'password' => 'irrelevant',
    ]);

    $minted = $this->mintCredential(['user_id' => (string) $user->id]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('principal', $user->id);
});

it('rejects a user-bound credential whose user no longer exists', function (): void {
    $minted = $this->mintCredential(['user_id' => '999999']);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertUnauthorized();

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('authenticates two same-named credentials independently, before and after renaming', function (): void {
    $first = $this->mintCredential(['name' => 'ci', 'subject_ref' => 'tenant-a']);
    $second = $this->mintCredential(['name' => 'deploy', 'subject_ref' => 'tenant-b']);

    $this->getJson('/bfc-guarded', ['Authorization' => $first->bearerHeader()])
        ->assertOk()->assertJsonPath('principal', $first->credential->id);
    $this->getJson('/bfc-guarded', ['Authorization' => $second->bearerHeader()])
        ->assertOk()->assertJsonPath('principal', $second->credential->id);

    // Renaming to a duplicate succeeds — no unique violation — and changes
    // neither credential's authentication outcome or identity.
    $second->credential->name = 'ci';
    $second->credential->save();

    expect(Credential::query()->where('name', 'ci')->count())->toBe(2);

    $this->getJson('/bfc-guarded', ['Authorization' => $first->bearerHeader()])
        ->assertOk()->assertJsonPath('principal', $first->credential->id);
    $this->getJson('/bfc-guarded', ['Authorization' => $second->bearerHeader()])
        ->assertOk()->assertJsonPath('principal', $second->credential->id);
});

it('never returns or logs the plaintext secret on any new code path', function (): void {
    $logged = [];
    Log::listen(function (MessageLogged $event) use (&$logged): void {
        $logged[] = $event;
    });

    $minted = $this->mintCredential();
    $revoked = $this->mintCredential(['revoked_at' => now()]);

    $ok = $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()]);
    $denied = $this->getJson('/bfc-guarded', ['Authorization' => $revoked->bearerHeader()]);

    $ok->assertOk();
    $denied->assertUnauthorized();

    expect($ok->getContent())->not->toContain($minted->plaintext())
        ->and($denied->getContent())->not->toContain($revoked->plaintext());

    foreach ($logged as $event) {
        expect($event->message)->not->toContain($minted->plaintext())
            ->and($event->message)->not->toContain($revoked->plaintext());

        $context = json_encode($event->context);

        expect($context)->not->toContain($minted->plaintext())
            ->and($context)->not->toContain($revoked->plaintext());
    }

    // The hash is at rest; the plaintext never is.
    expect(Credential::query()->where('secret_hash', $minted->plaintext())->exists())->toBeFalse()
        ->and($minted->credential->refresh()->secret_hash)->toBe(hash('sha256', $minted->plaintext()));
});

it('supports actingAsCredential for route tests', function (): void {
    $minted = $this->mintCredential();

    $this->actingAsCredential($minted)
        ->getJson('/bfc-guarded')
        ->assertOk()
        ->assertJsonPath('principal', $minted->credential->id);
});

it('refuses to serialize a minted test credential', function (): void {
    $minted = $this->mintCredential();

    expect(fn (): string => serialize($minted))->toThrow(LogicException::class);

    try {
        serialize($minted);
    } catch (Throwable $e) {
        expect($e->getMessage())->not->toContain($minted->plaintext());
    }
});

it('refuses to json-encode a minted test credential', function (): void {
    $minted = $this->mintCredential();

    expect(fn (): string|false => json_encode($minted))->toThrow(LogicException::class);

    try {
        json_encode($minted);
    } catch (Throwable $e) {
        expect($e->getMessage())->not->toContain($minted->plaintext());
    }

    // The headers a test actually needs keep working.
    expect($minted->bearerHeader())->toBe('Bearer '.$minted->plaintext())
        ->and($minted->basicHeader('u'))->toBe('Basic '.base64_encode('u:'.$minted->plaintext()));
});

it('does not leak the plaintext through native export and debug paths', function (): void {
    $minted = $this->mintCredential();
    $plaintext = $minted->plaintext();

    // The plaintext lives outside the object, so var_export, print_r,
    // var_dump, get_object_vars and a reflection property walk all come up
    // empty-handed.
    expect(var_export($minted, true))->not->toContain($plaintext)
        ->and(print_r($minted, true))->not->toContain($plaintext);

    ob_start();
    var_dump($minted);
    $dumped = (string) ob_get_clean();

    expect($dumped)->not->toContain($plaintext)
        ->and(json_encode(get_object_vars($minted)))->not->toContain($plaintext);

    foreach ((new ReflectionObject($minted))->getProperties() as $property) {
        expect($property->getValue($minted))->not->toBe($plaintext);
    }

    // And the carrier still presents it where the test needs it.
    expect($minted->bearerHeader())->toBe('Bearer '.$plaintext);
});

it('fails closed when session-user resolution throws', function (): void {
    Auth::provider('throwing', function (): never {
        throw new RuntimeException('session provider exploded');
    });

    config([
        'auth.providers.throwing_users' => ['driver' => 'throwing'],
        'auth.guards.broken_session' => ['driver' => 'session', 'provider' => 'throwing_users'],
        'built-for-cloud.credentials.session_guard' => 'broken_session',
    ]);

    $minted = $this->mintCredential();

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertUnauthorized();

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('still authenticates when no session guard is configured at all', function (): void {
    // The STRUCTURAL absence cases stay "no session user", not a failure.
    config(['built-for-cloud.credentials.session_guard' => 'no-such-guard']);

    $minted = $this->mintCredential();

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('principal', $minted->credential->id);
});

it('refuses wrong-purpose bearer and Basic secrets before declaration usage or principal publication', function (CredentialKind $kind): void {
    $declaration = new class implements CredentialDeclaration
    {
        public int $calls = 0;

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            $this->calls++;

            return true;
        }
    };
    app()->instance(CredentialDeclaration::class, $declaration);

    $wrong = $this->mintCredential([
        'kind' => $kind,
        'purpose' => CredentialPurpose::DashboardMetadata,
        'subject_type' => 'operator',
        'abilities' => ['metadata:read'],
    ]);
    $header = $kind === CredentialKind::Basic ? $wrong->basicHeader() : $wrong->bearerHeader();

    $this->getJson('/bfc-guarded', ['Authorization' => $header])->assertUnauthorized();

    expect($declaration->calls)->toBe(0)
        ->and($wrong->credential->refresh()->last_used_at)->toBeNull()
        ->and(Auth::guard('bfc')->hasUser())->toBeFalse()
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::FirstUsed->value)->count())->toBe(0);
})->with([CredentialKind::Bearer, CredentialKind::Basic]);

it('keeps validate purpose-aware and effect-free for bearer and Basic credentials', function (): void {
    $declaration = new class implements CredentialDeclaration
    {
        public int $calls = 0;

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            $this->calls++;

            return true;
        }
    };
    app()->instance(CredentialDeclaration::class, $declaration);

    $bearer = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => 'external_consumer',
    ]);
    $basic = $this->mintCredential([
        'kind' => CredentialKind::Basic,
        'purpose' => CredentialPurpose::SystemDeployment,
    ]);
    $wrongBearer = $this->mintCredential([
        'purpose' => CredentialPurpose::DashboardMetadata,
        'subject_type' => 'operator',
    ]);
    $wrongBasic = $this->mintCredential([
        'kind' => CredentialKind::Basic,
        'purpose' => CredentialPurpose::OperatorManagement,
        'subject_type' => 'operator',
    ]);
    $revoked = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => 'external_consumer',
        'revoked_at' => now(),
    ]);

    /** @var CredentialGuard $guard */
    $guard = Auth::guard('bfc');

    expect($guard->validate(['secret' => $bearer->plaintext()]))->toBeTrue()
        ->and($guard->validate(['secret' => $basic->plaintext()]))->toBeTrue()
        ->and($guard->validate(['secret' => $wrongBearer->plaintext()]))->toBeFalse()
        ->and($guard->validate(['secret' => $wrongBasic->plaintext()]))->toBeFalse()
        ->and($guard->validate(['secret' => $revoked->plaintext()]))->toBeFalse()
        ->and($guard->validate(['secret' => 'unknown']))->toBeFalse()
        ->and($declaration->calls)->toBe(0)
        ->and($guard->hasUser())->toBeFalse()
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::FirstUsed->value)->count())->toBe(0);

    foreach ([$bearer, $basic, $wrongBearer, $wrongBasic, $revoked] as $minted) {
        expect($minted->credential->refresh()->last_used_at)->toBeNull();
    }
});

it('resolves once per request rechecks every purpose set and runs accepted effects once', function (): void {
    config(['auth.guards.bfc.provider' => null]);
    Auth::forgetGuards();

    $declaration = new class implements CredentialDeclaration
    {
        public int $calls = 0;

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            $this->calls++;

            return true;
        }
    };
    app()->instance(CredentialDeclaration::class, $declaration);

    $minted = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => 'external_consumer',
    ]);
    $retrieved = 0;
    Credential::retrieved(function (Credential $credential) use ($minted, &$retrieved): void {
        if ($credential->id === $minted->credential->id) {
            $retrieved++;
        }
    });
    app()->instance('request', Request::create('/one', server: [
        'HTTP_AUTHORIZATION' => $minted->bearerHeader(),
    ]));

    /** @var CredentialGuard $guard */
    $guard = Auth::guard('bfc');

    expect($guard->credentialForPurposes([CredentialPurpose::Consumption])?->id)->toBe($minted->credential->id)
        ->and($guard->credentialForPurposes([CredentialPurpose::Mcp]))->toBeNull()
        ->and($guard->credentialForPurposes([CredentialPurpose::Consumption])?->id)->toBe($minted->credential->id)
        ->and($guard->credential()?->id)->toBe($minted->credential->id)
        ->and($guard->user()?->getAuthIdentifier())->toBe($minted->credential->id)
        ->and($retrieved)->toBe(1)
        ->and($declaration->calls)->toBe(1)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $minted->credential->id)
            ->where('event', LifecycleEventType::FirstUsed->value)
            ->count())->toBe(1);
});

it('does not let a purpose-specific cache authorize the ordinary guard set', function (): void {
    config(['auth.guards.bfc.provider' => null]);
    Auth::forgetGuards();

    $minted = $this->mintCredential([
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => 'external_consumer',
    ]);
    app()->instance('request', Request::create('/mcp', server: [
        'HTTP_AUTHORIZATION' => $minted->bearerHeader(),
    ]));

    /** @var CredentialGuard $guard */
    $guard = Auth::guard('bfc');

    expect($guard->credentialForPurposes([CredentialPurpose::Mcp])?->id)->toBe($minted->credential->id)
        ->and($guard->user())->toBeNull()
        ->and($guard->credential())->toBeNull()
        ->and($guard->check())->toBeFalse()
        ->and($guard->guest())->toBeTrue()
        ->and($guard->id())->toBeNull()
        ->and($guard->credentialForPurposes([CredentialPurpose::Mcp])?->id)->toBe($minted->credential->id)
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $minted->credential->id)
            ->where('event', LifecycleEventType::FirstUsed->value)
            ->count())->toBe(1);
});

it('discards every cached row and principal when the Request object changes', function (): void {
    config(['auth.guards.bfc.provider' => null]);
    Auth::forgetGuards();

    $first = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => 'external_consumer',
    ]);
    $second = $this->mintCredential(['purpose' => CredentialPurpose::SystemDeployment]);

    app()->instance('request', Request::create('/first', server: [
        'HTTP_AUTHORIZATION' => $first->bearerHeader(),
    ]));

    /** @var CredentialGuard $guard */
    $guard = Auth::guard('bfc');
    expect($guard->credential()?->id)->toBe($first->credential->id);

    app()->instance('request', Request::create('/second', server: [
        'HTTP_AUTHORIZATION' => $second->bearerHeader(),
    ]));

    expect($guard->credential()?->id)->toBe($second->credential->id)
        ->and($guard->id())->toBe($second->credential->id)
        ->and($first->credential->refresh()->last_used_at)->not->toBeNull()
        ->and($second->credential->refresh()->last_used_at)->not->toBeNull();
});
