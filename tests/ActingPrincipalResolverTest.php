<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedPrincipalUnsupported;
use ArtisanBuild\BuiltForCloud\Exceptions\NoActingPrincipal;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\User as CanonicalUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;

uses(RefreshDatabase::class);

function resolverTestUser(string $name, ?int $id = null): User
{
    $user = new User;
    $user->forceFill(array_filter([
        'id' => $id,
        'name' => $name,
        'email' => strtolower(str_replace(' ', '.', $name)).'@example.com',
        'password' => 'irrelevant',
    ], static fn (mixed $value): bool => $value !== null));
    $user->save();

    return $user;
}

function resolverTestActor(int $id = 7): DelegatedActor
{
    $assertion = consoleAssertionFor(subject: 'resolver-actor-'.$id);
    $actor = new DelegatedActor;
    $actor->forceFill([
        'id' => $id,
        'identity_hash' => DelegatedActor::identityHash($assertion->issuer, $assertion->subject),
        'issuer' => $assertion->issuer,
        'subject' => $assertion->subject,
        'last_handoff_display_name' => $assertion->displayName,
        'last_handoff_on_behalf_of' => $assertion->onBehalfOf,
        'last_handoff_role' => $assertion->role->value,
    ])->save();

    return $actor;
}

it('prefers the exact published assertion actor over a different request principal', function (): void {
    $localUser = resolverTestUser('Local Seven', 7);
    $actor = resolverTestActor(7);
    $request = Request::create('/mcp', 'POST');
    $published = RequestAssertion::publish($request, $actor, consoleAssertionFor(subject: 'resolver-actor-7'));

    // Pin precedence independently of publish() replacing the resolver.
    $request->setUserResolver(static fn (): User => $localUser);

    $resolver = app(ActingPrincipalResolver::class);
    $acting = $resolver->acting($request);

    expect($acting)->toBe($published)
        ->and($acting->principal)->toBe($actor)
        ->and($acting->identifier())->toBe('bfc-console:7')
        ->and($resolver->localUser($request))->toBeNull();
});

it('takes a direct credential from the supplied request instead of the default session guard', function (): void {
    $sessionUser = resolverTestUser('Session User');
    $boundUser = resolverTestUser('Bound User');
    $credential = Credential::factory()->create(['user_id' => (string) $boundUser->getKey()]);
    $request = Request::create('/mcp', 'POST');
    $request->setUserResolver(static fn (): Credential => $credential);
    $this->actingAs($sessionUser);

    $resolver = app(ActingPrincipalResolver::class);
    $acting = $resolver->acting($request);
    $localUser = $resolver->localUser($request);

    expect($acting->principal)->toBe($credential)
        ->and($acting->identifier())->toBe($credential->getAuthIdentifier())
        ->and($acting->guard)->toBeNull()
        ->and($localUser)->toBeInstanceOf(CanonicalUser::class)
        ->and($localUser?->getAuthIdentifier())->toBe($boundUser->getAuthIdentifier());
});

it('supports an exact local session user and nobody acting', function (): void {
    $user = resolverTestUser('Session User');
    $sessionRequest = Request::create('/dashboard', 'GET');
    $sessionRequest->setUserResolver(static fn (): User => $user);
    $emptyRequest = Request::create('/dashboard', 'GET');

    $resolver = app(ActingPrincipalResolver::class);
    $session = $resolver->acting($sessionRequest);
    $nobody = $resolver->acting($emptyRequest);

    expect($session->principal)->toBe($user)
        ->and($resolver->localUser($sessionRequest))->toBe($user)
        ->and($nobody->principal)->toBeNull()
        ->and($nobody->check())->toBeFalse();
});

it('does not project either containment half through session or direct credential arrivals', function (string $arrival, string $containment): void {
    config(['built-for-cloud.credentials.declaration' => SelfServiceDeclaration::class]);

    $user = resolverTestUser('Contained Local User');
    $userId = (string) $user->getAuthIdentifier();
    OffboardedSubject::query()->create([
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$userId,
        'user_id' => $containment === 'user' ? $userId : OffboardedSubject::SUBJECT_ROW,
        'offboarded_at' => now(),
    ]);

    $request = Request::create($arrival === 'credential' ? '/mcp' : '/dashboard', $arrival === 'credential' ? 'POST' : 'GET');

    if ($arrival === 'credential') {
        $credential = Credential::factory()->create(['user_id' => $userId]);
        $request->setUserResolver(static fn (): Credential => $credential);
    } else {
        $request->setUserResolver(static fn (): User => $user);
    }

    expect(app(ActingPrincipalResolver::class)->localUser($request))->toBeNull();
})->with([
    'session, per-user row' => ['session', 'user'],
    'session, subject row only' => ['session', 'subject'],
    'credential, per-user row' => ['credential', 'user'],
    'credential, subject row only' => ['credential', 'subject'],
]);

it('requires each supported assertion credential and session arrival shape', function (): void {
    $actor = resolverTestActor();
    $assertionRequest = Request::create('/mcp', 'POST');
    RequestAssertion::publish($assertionRequest, $actor, consoleAssertionFor(subject: 'resolver-actor-7'));

    $credential = Credential::factory()->create();
    $credentialRequest = Request::create('/mcp', 'POST');
    $credentialRequest->setUserResolver(static fn (): Credential => $credential);

    $user = resolverTestUser('Session User');
    $sessionRequest = Request::create('/dashboard', 'GET');
    $sessionRequest->setUserResolver(static fn (): User => $user);

    $resolver = app(ActingPrincipalResolver::class);

    expect($resolver->require($assertionRequest)->principal)->toBe($actor)
        ->and($resolver->require($credentialRequest)->principal)->toBe($credential)
        ->and($resolver->require($sessionRequest)->principal)->toBe($user);
});

it('names nobody and an unverified delegated source with different exceptions', function (): void {
    $resolver = app(ActingPrincipalResolver::class);
    $emptyRequest = Request::create('/mcp', 'POST');

    expect(fn () => $resolver->require($emptyRequest))->toThrow(NoActingPrincipal::class);

    $actor = resolverTestActor();
    $bareDelegatedRequest = Request::create('/mcp', 'POST');
    $bareDelegatedRequest->setUserResolver(static fn (): DelegatedActor => $actor);

    expect($resolver->acting($bareDelegatedRequest)->principal)->toBeNull()
        ->and($resolver->localUser($bareDelegatedRequest))->toBeNull();
    expect(fn () => $resolver->require($bareDelegatedRequest))->toThrow(DelegatedPrincipalUnsupported::class);
});
