<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DelegatedActorBoundToCanonicalUser;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DelegatedActorReturnedAsCanonicalUser;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Tests\PublicSurfaceScan;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

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
        ->and($refreshed->fresh()?->deactivated_at)->not->toBeNull();
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

    // The adversarial case: the bare numeric key — exactly what a
    // `users` id looks like — does not sit in the reserved namespace.
    expect(DelegatedActor::isReservedIdentifier((string) $user->getAuthIdentifier()))->toBeFalse()
        ->and(DelegatedActor::isReservedIdentifier(DelegatedActor::IDENTIFIER_PREFIX))->toBeTrue();

    // ...and the crossing does not work in the other direction either:
    // the app's own user provider does not answer for a qualified id.
    expect(Auth::createUserProvider('users')?->retrieveById($actor->getAuthIdentifier()))->toBeNull();
});

it('recognises every spelling inside the reserved namespace, well-formed or not, without touching the database', function (string $suffix): void {
    // The reserved-namespace rule is prefix-shaped on purpose: even a
    // value that names no row must be recognised as reserved, because it
    // must never reach a user provider whose own coercion decides what
    // it means. The check is pure — no query, by construction.
    consoleActor();

    DB::enableQueryLog();
    DB::flushQueryLog();

    expect(DelegatedActor::isReservedIdentifier(DelegatedActor::IDENTIFIER_PREFIX.$suffix))->toBeTrue()
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

it('keeps bare keys outside the reserved namespace, so a users id is never mistaken for a delegated one', function (): void {
    $actor = consoleActor();

    expect(DelegatedActor::isReservedIdentifier($actor->getAuthIdentifier()))->toBeTrue()
        ->and(DelegatedActor::isReservedIdentifier((string) $actor->getKey()))->toBeFalse()
        ->and(DelegatedActor::isReservedIdentifier(null))->toBeFalse()
        ->and(DelegatedActor::isReservedIdentifier(7))->toBeFalse();
});

// ─── AC3: a delegated actor is not a user ───────────────────────────────────

it('has no password or remember-token column', function (): void {
    expect(Schema::hasColumn('bfc_delegated_actors', 'password'))->toBeFalse()
        ->and(Schema::hasColumn('bfc_delegated_actors', 'remember_token'))->toBeFalse()
        ->and(Schema::hasColumn('bfc_delegated_actors', 'deactivated_at'))->toBeTrue();
});

it('derives the complete public surface and pins its sole request-context identity pairing', function (): void {
    $columns = Schema::getColumnListing('bfc_delegated_actors');
    sort($columns);
    $kinds = CredentialKind::values();
    sort($kinds);
    $surface = PublicSurfaceScan::discoverDeclaredPublicMethods(dirname(__DIR__).'/src');

    expect($columns)->toBe([
        'created_at',
        'deactivated_at',
        'id',
        'identity_hash',
        'issuer',
        'last_handoff_display_name',
        'last_handoff_on_behalf_of',
        'last_handoff_role',
        'subject',
        'updated_at',
    ])->and($kinds)->toBe(['asymmetric', 'basic', 'bearer', 'hmac'])
        ->and(PublicSurfaceScan::canonicalUserBindings($surface))->toBe([]);
});

it('discovers and reports a fixture that publicly binds a delegated actor to a canonical user', function (): void {
    $surface = PublicSurfaceScan::discoverDeclaredPublicMethods(
        dirname(__DIR__).'/src',
        [
            __DIR__.'/Fixtures/DelegatedActorBoundToCanonicalUser.php',
            __DIR__.'/Fixtures/DelegatedActorReturnedAsCanonicalUser.php',
        ],
    );

    expect(PublicSurfaceScan::canonicalUserBindings($surface))->toBe([
        'tests/Fixtures/DelegatedActorBoundToCanonicalUser.php:15 ['.DelegatedActorBoundToCanonicalUser::class.'::bind($user,$actor)]',
        'tests/Fixtures/DelegatedActorReturnedAsCanonicalUser.php:13 ['.DelegatedActorReturnedAsCanonicalUser::class.'::userFor($actor):return]',
        'tests/Fixtures/DelegatedActorReturnedAsCanonicalUser.php:15 ['.DelegatedActorReturnedAsCanonicalUser::class.'::authenticatableFor($actor):return]',
        'tests/Fixtures/DelegatedActorReturnedAsCanonicalUser.php:17 ['.DelegatedActorReturnedAsCanonicalUser::class.'::userOrFalseFor($actor):return]',
    ]);
});

it('carries password and remember-token values nothing can turn into a match', function (): void {
    $actor = consoleActor();

    // Inert rather than throwing: no caller asks, and every value here
    // is one a hasher or a provider already treats as "never matches".
    expect($actor->getAuthPassword())->toBe('')
        ->and(Hash::check('anything', $actor->getAuthPassword()))->toBeFalse()
        ->and($actor->getAuthPasswordName())->toBe('')
        ->and($actor->getRememberToken())->toBeNull()
        ->and($actor->getRememberTokenName())->toBe('');

    $actor->setRememberToken('anything');

    expect($actor->getRememberToken())->toBeNull()
        ->and($actor->fresh()?->getRememberToken())->toBeNull();
});
