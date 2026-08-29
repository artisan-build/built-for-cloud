<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActorProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Route::middleware([StartSession::class])->get('/delegated-identity', fn (): array => [
        'delegated' => auth(ConsoleGuardConfiguration::GUARD)->id(),
        'local' => auth('web')->id(),
    ]);
});

function delegatedTestUser(string $email = 'local@example.com'): User
{
    return User::query()->create([
        'name' => 'Local User',
        'email' => $email,
        'password' => 'irrelevant',
    ]);
}

// ─── AC1: the shadow actor is keyed on issuer + subject ─────────────────────

it('upserts one actor per issuer+subject and refreshes its last-handoff record', function (): void {
    $first = consoleActor(displayName: 'Jane Operator', role: ConsoleRole::Admin);

    expect(DelegatedActor::query()->count())->toBe(1);

    $second = consoleActor(displayName: 'Jane Renamed', role: ConsoleRole::Member, onBehalfOf: 'Acme Agency');

    expect(DelegatedActor::query()->count())->toBe(1)
        ->and($second->getKey())->toBe($first->getKey())
        ->and($second->last_handoff_display_name)->toBe('Jane Renamed')
        ->and($second->last_handoff_role)->toBe(ConsoleRole::Member)
        ->and($second->last_handoff_on_behalf_of)->toBe('Acme Agency');
});

it('treats the same subject from a different issuer as a different actor', function (): void {
    $one = consoleActor(issuer: 'https://scalpels.test', subject: 'operator_42');
    $two = consoleActor(issuer: 'https://other-issuer.test', subject: 'operator_42');

    expect(DelegatedActor::query()->count())->toBe(2)
        ->and($two->getKey())->not->toBe($one->getKey());
});

// ─── Identity is byte-exact, not collation-exact ────────────────────────────

it('treats subjects differing only in case as two different actors', function (): void {
    $upper = consoleActor(subject: 'OperatorA');
    $lower = consoleActor(subject: 'operatora');

    expect(DelegatedActor::query()->count())->toBe(2)
        ->and($lower->getKey())->not->toBe($upper->getKey())
        ->and($lower->identity_hash)->not->toBe($upper->identity_hash);
})->note('Byte-exactness comes from the digest, not from the driver: this suite runs sqlite, whose default collation is already binary, so the assertion would also pass on a schema that relied on collation. What it pins is that identity is computed in PHP from the raw bytes — the case MySQL\'s default utf8mb4_0900_ai_ci would otherwise conflate.');

it('treats issuers differing only in case as two different actors', function (): void {
    consoleActor(issuer: 'https://Scalpels.test');
    consoleActor(issuer: 'https://scalpels.test');

    expect(DelegatedActor::query()->count())->toBe(2);
});

it('cannot be confused by shifting the boundary between issuer and subject', function (): void {
    // Length-delimited hashing: without the lengths, 'ab' + 'c' and
    // 'a' + 'bc' would concatenate to the same string.
    expect(DelegatedActor::identityHash('ab', 'c'))
        ->not->toBe(DelegatedActor::identityHash('a', 'bc'))
        ->and(DelegatedActor::identityHash('a:b', 'c'))
        ->not->toBe(DelegatedActor::identityHash('a', 'b:c'));
});

it('does not reactivate a deactivated actor on a later handoff', function (): void {
    $actor = consoleActor();
    $actor->forceFill(['deactivated_at' => now()])->save();

    $refreshed = consoleActor(displayName: 'Jane Again');

    expect($refreshed->getKey())->toBe($actor->getKey())
        ->and($refreshed->last_handoff_display_name)->toBe('Jane Again')
        ->and($refreshed->fresh()?->deactivated_at)->not->toBeNull()
        ->and((new DelegatedActorProvider)->retrieveById($actor->getAuthIdentifier()))->toBeNull();
});

// ─── AC2: the identity is type-qualified and cannot collide with a users id ──

it('type-qualifies the delegated identity so it can never equal a users id', function (): void {
    // Both tables' first row: the ids genuinely collide, and the
    // qualifier is the only thing keeping the principals apart. Drop it
    // and this test goes red on the very next line.
    $user = delegatedTestUser();
    $actor = consoleActor();

    expect($user->getKey())->toBe($actor->getKey())
        ->and($actor->getAuthIdentifier())->toBe('bfc-console:'.$actor->getKey());

    $provider = new DelegatedActorProvider;

    // The adversarial case: the bare numeric key — exactly what a
    // `users` id looks like — resolves to nothing here.
    expect($provider->retrieveById($user->getAuthIdentifier()))->toBeNull()
        ->and($provider->retrieveById((string) $user->getAuthIdentifier()))->toBeNull()
        ->and($provider->retrieveById(DelegatedActor::IDENTIFIER_PREFIX))->toBeNull()
        ->and($provider->retrieveById($actor->getAuthIdentifier())?->getKey())->toBe($actor->getKey());

    // ...and the crossing does not work in the other direction either:
    // the app's own user provider does not answer for a qualified id.
    expect(Auth::createUserProvider('users')?->retrieveById($actor->getAuthIdentifier()))->toBeNull();
});

it('refuses a non-canonical delegated identifier before it ever reaches the database', function (string $suffix): void {
    consoleActor();

    DB::enableQueryLog();
    DB::flushQueryLog();

    expect((new DelegatedActorProvider)->retrieveById(DelegatedActor::IDENTIFIER_PREFIX.$suffix))->toBeNull()
        ->and(DB::getQueryLog())->toBe([]);
})->with([
    'trailing junk' => ['1junk'],
    'leading zero' => ['01'],
    'zero' => ['0'],
    'negative' => ['-1'],
    'signed' => ['+1'],
    'decimal' => ['1.0'],
    'leading space' => [' 1'],
    'hex' => ['0x1'],
    'oversized' => ['999999999999999999999999'],
    'empty' => [''],
]);

it('refuses a delegated identifier whose row would answer with a different one', function (): void {
    $actor = consoleActor();

    // The canonical form resolves; nothing else that names the same row
    // does, because the round trip has to be character-exact.
    expect((new DelegatedActorProvider)->retrieveById($actor->getAuthIdentifier())?->getKey())->toBe($actor->getKey())
        ->and((new DelegatedActorProvider)->retrieveById(DelegatedActor::IDENTIFIER_PREFIX.'0'.$actor->getKey()))->toBeNull();
});

it('reports the type-qualified identity through the guard while a local session reports its own', function (): void {
    $user = delegatedTestUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    $this->getJson('/delegated-identity')
        ->assertOk()
        ->assertJsonPath('delegated', 'bfc-console:'.$actor->getKey())
        ->assertJsonPath('local', $user->getKey());
});

// ─── AC3: a delegated actor is not a user ───────────────────────────────────

it('has no password or remember-token column', function (): void {
    expect(Schema::hasColumn('bfc_delegated_actors', 'password'))->toBeFalse()
        ->and(Schema::hasColumn('bfc_delegated_actors', 'remember_token'))->toBeFalse()
        ->and(Schema::hasColumn('bfc_delegated_actors', 'deactivated_at'))->toBeTrue();
});

it('refuses every credential lookup unconditionally, not merely the ones that do not match', function (): void {
    $actor = consoleActor();
    $provider = new DelegatedActorProvider;

    // The distinguishing assertion: validateCredentials is handed the
    // ACTUAL principal and still says no. A stock provider would only
    // answer false because the secret was wrong; this one has nothing to
    // compare and never says yes.
    expect($provider->validateCredentials($actor, ['password' => 'secret']))->toBeFalse()
        ->and($provider->validateCredentials($actor, []))->toBeFalse()
        ->and($provider->retrieveByCredentials(['email' => 'jane@example.com', 'password' => 'secret']))->toBeNull()
        ->and($provider->retrieveByCredentials([]))->toBeNull()
        ->and($provider->retrieveByToken($actor->getAuthIdentifier(), 'remember-me'))->toBeNull();

    expect(auth(ConsoleGuardConfiguration::GUARD)->check())->toBeFalse();
});

it('has no credential-shaped entry point on the guard at all', function (string $method): void {
    // §4.3's "no login path" is STRUCTURAL: these methods do not exist
    // on the console guard, so there is nothing to call and nothing to
    // refuse. A StatefulGuard would have carried every one of them.
    expect(method_exists(auth(ConsoleGuardConfiguration::GUARD), $method))->toBeFalse();
})->with(['attempt', 'once', 'loginUsingId', 'onceUsingId', 'viaRemember', 'basic', 'onceBasic', 'attemptWhen']);

it('answers false to the one credential-shaped method the Guard contract demands, for every input', function (): void {
    $actor = consoleActor();
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard->validate([]))->toBeFalse()
        ->and($guard->validate(['email' => 'jane@example.com', 'password' => 'secret']))->toBeFalse()
        ->and($guard->validate(['id' => $actor->getAuthIdentifier()]))->toBeFalse();
});

it('carries password and remember-token values nothing can turn into a match', function (): void {
    $actor = consoleActor();

    // Inert rather than throwing: no caller asks (see the guard and the
    // provider), and every value here is one a hasher or a provider
    // already treats as "never matches".
    expect($actor->getAuthPassword())->toBe('')
        ->and(Hash::check('anything', $actor->getAuthPassword()))->toBeFalse()
        ->and($actor->getAuthPasswordName())->toBe('')
        ->and($actor->getRememberToken())->toBeNull()
        ->and($actor->getRememberTokenName())->toBe('');

    $actor->setRememberToken('anything');

    expect($actor->getRememberToken())->toBeNull()
        ->and($actor->fresh()?->getRememberToken())->toBeNull();

    (new DelegatedActorProvider)->updateRememberToken($actor, 'anything');

    expect($actor->fresh()?->getRememberToken())->toBeNull();
});
