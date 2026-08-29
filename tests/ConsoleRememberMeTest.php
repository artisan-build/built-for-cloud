<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActorProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RecordingDelegatedActorProvider;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Recaller;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * REMEMBER-ME ON THE DELEGATED GUARD — driven, not argued.
 *
 * Two earlier revisions of this package's docblocks got this wrong in
 * the same direction, claiming the remember-me path was UNREACHABLE.
 * It is not. `SessionGuard::user()` looks for a recaller cookie whenever
 * the session carries no identifier, so a syntactically valid,
 * correctly-shaped `remember_bfc-console_*` cookie — one left behind by
 * an earlier deployment that used this guard name with a stock provider,
 * say — is decrypted and handed to the provider.
 *
 * The security result is nonetheless correct, and these tests are what
 * make that a VERIFIED statement rather than a reachability argument:
 * the branch is entered, the provider answers null for every input, and
 * nobody authenticates. "Fail-closed", not "absent".
 *
 * The routes carry no `EncryptCookies`, so the recaller is read verbatim
 * from the request — which is what lets a test hand the guard a
 * well-formed one without reproducing the framework's cookie crypto.
 */
beforeEach(function (): void {
    RecordingDelegatedActorProvider::reset();

    Route::middleware([StartSession::class])->get('/remember-probe', fn (): array => [
        'delegated' => auth(ConsoleGuardConfiguration::GUARD)->id(),
        'checked' => auth(ConsoleGuardConfiguration::GUARD)->check(),
    ]);
});

/**
 * The cookie name Laravel derives for this guard's recaller, and the
 * three-segment payload {@see Recaller} expects.
 */
function recallerCookieName(): string
{
    return 'remember_'.ConsoleGuardConfiguration::GUARD.'_'.sha1(SessionGuard::class);
}

function recallerCookieValue(DelegatedActor $actor): string
{
    return implode('|', [$actor->getAuthIdentifier(), Str::random(60), 'irrelevant-password-hash']);
}

// ─── The branch is REACHABLE ────────────────────────────────────────────────

it('hands a well-formed recaller cookie to the provider, which is what makes the branch reachable', function (): void {
    $actor = consoleActor();

    // Swap in a provider that records what the framework asked it,
    // delegating every answer to the real one — so what is observed is
    // the real provider's behaviour, not a stand-in's.
    Auth::provider(ConsoleGuardConfiguration::PROVIDER, fn (): RecordingDelegatedActorProvider => new RecordingDelegatedActorProvider);
    Auth::forgetGuards();

    // `withCredentials()` because a JSON test request sends no cookies
    // without it, and `withUnencryptedCookie()` because these routes
    // carry no EncryptCookies — the guard must read the recaller
    // verbatim, exactly as it would behind a real cookie stack.
    $this->withCredentials()->withUnencryptedCookie(recallerCookieName(), recallerCookieValue($actor));

    $this->getJson('/remember-probe')
        ->assertOk()
        // FAIL-CLOSED: nobody authenticates.
        ->assertJsonPath('delegated', null)
        ->assertJsonPath('checked', false);

    // ...and the branch really was entered. Without this assertion the
    // test above would pass just as well if Laravel never looked, which
    // is exactly the wrong conclusion two revisions of the docblock drew.
    expect(RecordingDelegatedActorProvider::$tokenLookups)->not->toBe([])
        ->and(RecordingDelegatedActorProvider::$tokenLookups[0][0])->toBe($actor->getAuthIdentifier());
});

it('is the provider that closes it: retrieveByToken answers null for the very pair the branch passes it', function (): void {
    $actor = consoleActor();
    $recaller = new Recaller(recallerCookieValue($actor));

    expect($recaller->valid())->toBeTrue()
        ->and($recaller->id())->toBe($actor->getAuthIdentifier())
        ->and((new DelegatedActorProvider)->retrieveByToken($recaller->id(), $recaller->token()))->toBeNull();
});

it('writes no session and starts no delegated session from a recaller', function (): void {
    $actor = consoleActor();

    $this->withCredentials()->withUnencryptedCookie(recallerCookieName(), recallerCookieValue($actor));

    $response = $this->getJson('/remember-probe')->assertOk();

    // A successful recall would have called updateSession() — put the
    // identifier and regenerate — and fired a Login event. None of it
    // happened.
    $response->assertSessionMissing(consoleGuardSessionKey());

    foreach (ConsoleSession::keys() as $key) {
        $response->assertSessionMissing($key);
    }
});

// ─── The model's own remember-token answers, on the paths that read them ────

it('cannot be recalled by a stock Eloquent provider either, because its remember token is null', function (): void {
    $actor = consoleActor();

    // Not a hypothetical: this is the configuration an app produces by
    // pointing an ordinary `eloquent` provider at the delegated actors.
    // `EloquentUserProvider::retrieveByToken()` refuses on a falsy
    // `getRememberToken()`, which this model's always is.
    $provider = new EloquentUserProvider(Hash::getFacadeRoot(), DelegatedActor::class);

    expect($actor->getRememberToken())->toBeNull()
        ->and($provider->retrieveById($actor->getKey())?->getAuthIdentifier())->toBe($actor->getAuthIdentifier())
        ->and($provider->retrieveByToken($actor->getKey(), 'any-token'))->toBeNull();
});

it('absorbs a remember-token write without persisting one', function (): void {
    // setRememberToken() is a no-op rather than a throw. Nothing in this
    // package reaches it — ConsoleGuard never remembers a login, and its
    // logout() does not call the framework's, which is the only caller
    // that would cycle a token — so this drives it directly and asserts
    // the only thing that matters: no token is stored, and no column
    // appears to store one in.
    $actor = consoleActor();

    $actor->setRememberToken('a-token-somebody-tried-to-set');
    $actor->save();

    expect($actor->getRememberToken())->toBeNull()
        ->and($actor->fresh()?->getRememberToken())->toBeNull()
        ->and($actor->getRememberTokenName())->toBe('')
        ->and(array_key_exists('remember_token', $actor->fresh()?->getAttributes() ?? []))->toBeFalse();

    (new DelegatedActorProvider)->updateRememberToken($actor, 'another-token');

    expect($actor->fresh()?->getRememberToken())->toBeNull();
});

it('never queues a recaller cookie of its own on a real redemption', function (): void {
    // The only recaller that can exist for this guard is one this
    // package did not write. `redeem()` logs in with remembering off and
    // there is no other login path, so a redemption leaves no
    // remember-me cookie behind.
    $response = $this->get('/remember-probe');

    consoleRedeem();

    /** @var ConsoleGuard $guard */
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard->check())->toBeTrue();

    $queued = collect(cookie()->getQueuedCookies())
        ->map(fn ($cookie): string => $cookie->getName())
        ->all();

    expect($queued)->not->toContain(recallerCookieName())
        ->and($response->headers->getCookies())->toBeArray();
});
