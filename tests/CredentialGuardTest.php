<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;
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
    $minted = $this->mintCredential(['kind' => CredentialKind::Basic]);

    $this->getJson('/bfc-guarded', ['Authorization' => $minted->basicHeader('any-username')])
        ->assertOk()
        ->assertJsonPath('principal', $minted->credential->id);

    expect($minted->credential->refresh()->last_used_at)->not->toBeNull();
});

it('does not authenticate a bearer presentation against a basic credential or vice versa', function (): void {
    $basic = $this->mintCredential(['kind' => CredentialKind::Basic]);
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

it('denies the fallback token on the bfc guard and resolves no credential', function (): void {
    config(['built-for-cloud.fallback_token' => 'the-fallback-secret']);

    // A resolvable row must be present: the denial is only meaningful when
    // authenticating the fallback secret would have resolved something.
    $minted = $this->mintCredential();

    $this->getJson('/bfc-guarded', ['Authorization' => 'Bearer the-fallback-secret'])
        ->assertUnauthorized();

    expect(Credential::query()->whereNotNull('last_used_at')->count())->toBe(0);

    // The row itself stays fully resolvable — the denial is about the
    // presented secret, not a dead store.
    $this->getJson('/bfc-guarded', ['Authorization' => $minted->bearerHeader()])
        ->assertOk();

    // The legacy registry keeps its fallback behaviour for legacy consumers.
    expect((new TokenRegistry)->resolve('the-fallback-secret'))->toBe(TokenRegistry::FALLBACK);
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
