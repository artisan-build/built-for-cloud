<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedReturnTo;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

function intendedRedirectUser(): User
{
    $user = User::query()->create([
        'name' => 'Deep link visitor',
        'email' => 'deep-link@example.test',
        'password' => Hash::make('correct horse battery staple'),
    ]);
    $user->forceFill([
        'role' => UserRole::Admin->value,
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => 'deep-link@example.test',
    ])->save();

    return $user;
}

/**
 * The `intended` the gate emits for a request whose REQUEST_URI is the
 * supplied one, read off the redirect it answers a guest with.
 *
 * The middleware is driven directly because the hostile forms this is
 * about cannot be delivered through the test HTTP client: the router
 * matches on the DECODED PATH INFO, so a request whose path is
 * `//evil.example/…` or `/%2F%2Fevil.example` matches no route and is a
 * 404 before any gate runs. The request URI, which is what the gate
 * reads, keeps the hostile spelling — and in production a proxy or a
 * handwritten request line can hand the application exactly that pair.
 */
function standaloneGateIntended(string $requestUri): ?string
{
    $request = Request::create('/bfc/me/sessions', 'GET');
    $request->server->set('REQUEST_URI', $requestUri);
    app()->instance('request', $request);

    $response = app(EnsureUserIsAuthenticated::class)->handle(
        $request,
        static fn (): Response => throw new RuntimeException('A guest request reached the route behind the gate.'),
    );

    expect($response->getStatusCode())->toBe(302);
    $location = (string) $response->headers->get('Location');
    $query = (string) parse_url($location, PHP_URL_QUERY);
    parse_str($query, $parameters);

    expect($location)->toStartWith(route('bfc.login'));

    return isset($parameters['intended']) && is_string($parameters['intended'])
        ? $parameters['intended']
        : null;
}

it('carries a standalone deep link through sign-in and lands the person back on it', function (): void {
    // The authority table seeds `standalone`, so this is what a fork gets
    // before it ever connects to a control plane.
    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone);

    $user = intendedRedirectUser();
    $deepLink = '/bfc/me/sessions?test-created-view=all';

    $this->get($deepLink)->assertRedirect(route('bfc.login', ['intended' => $deepLink]));

    $this->get(route('bfc.login', ['intended' => $deepLink], false))
        ->assertOk()
        ->assertSeeHtml('name="intended" value="'.e($deepLink).'"');

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.202.7'])->post('/bfc/login', [
        'email' => $user->email,
        'password' => 'correct horse battery staple',
        'intended' => $deepLink,
    ])->assertRedirect($deepLink);

    $this->get($deepLink)->assertOk();
});

it('answers a json request the same way it always did', function (): void {
    $this->getJson('/bfc/me/sessions')->assertUnauthorized();
    $this->getJson('/dashboard')->assertUnauthorized();
});

it('drops a hostile request URI for the server-chosen destination', function (string $requestUri, string $expected): void {
    $intended = standaloneGateIntended($requestUri);

    expect($intended)->toBe($expected)
        // Whatever is emitted is itself a value this package would accept
        // back: the gate never hands a browser a cleaned-up hostile form.
        ->and(ManagedReturnTo::relative($intended))->toBe($intended)
        ->and($intended)->not->toContain('evil.example');
})->with([
    'protocol-relative' => ['//evil.example/bfc/me/sessions', '/dashboard'],
    'backslash host' => ['/\\evil.example', '/dashboard'],
    'unrooted encoded slashes' => ['%2F%2Fevil.example', '/dashboard'],
    'encoded protocol-relative' => ['/%2F%2Fevil.example', '/dashboard'],
    'double-encoded protocol-relative' => ['/%252F%252Fevil.example', '/dashboard'],
    'encoded backslash' => ['/%5Cevil.example', '/dashboard'],
    'encoded CRLF in the path' => ['/safe%0d%0aLocation:%20https://evil.example', '/dashboard'],
    'encoded CRLF in the query' => ['/safe?x=%0d%0aLocation:%20https://evil.example', '/dashboard'],
    'traversal segment' => ['/bfc/me/../../evil.example', '/dashboard'],
    'over the length bound' => ['/'.str_repeat('a', 2100), '/dashboard'],
    'empty' => ['', '/dashboard'],
    // An absolute request URI never reaches the gate as one: a proxy-style
    // REQUEST_URI is reduced to its path by the request layer, so what the
    // gate reads is already relative and already same-origin.
    'absolute url' => ['https://evil.example/bfc/me/sessions', '/bfc/me/sessions'],
    'absolute url with no path' => ['https://evil.example', '/dashboard'],
]);

it('drops a hostile route parameter delivered over real HTTP', function (string $path): void {
    $this->get($path)->assertRedirect(route('bfc.login', ['intended' => '/dashboard']));
})->with([
    'encoded backslash' => ['/bfc/transitions/proposals/%5Cevil.example'],
    'double-encoded backslash' => ['/bfc/transitions/proposals/%255Cevil.example'],
    'traversal segment' => ['/bfc/transitions/proposals/%2e%2e'],
    'encoded CRLF' => ['/bfc/transitions/proposals/%0d%0aevil.example'],
]);
