<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnguardedCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Tests\ManagedIngressManifest;

/** @return array<class-string, string> */
function correctedManagedIngressManifest(): array
{
    return [
        CredentialGuard::class => 'adapt',
        ConsoleGuard::class => 'deferred — resolved by P5 transport consolidation',
        BasicAuthenticator::class => 'adapt',
        BearerAuthenticator::class => 'adapt',
        CredentialResolver::class => 'adapt',
        EnsureUserIsAuthenticated::class => 'adapt',
        EnsureUserIsAdmin::class => 'adapt',
        EnsureConsoleSession::class => 'deferred — resolved by P5 transport consolidation',
        AuthenticateMcp::class => 'deferred — resolved by P5 transport consolidation',
        EnsureAdminToken::class => 'deferred — resolved by P5 transport consolidation',
        EnsureCredentialAdmin::class => 'adapt',
        EnsureCredentialAbility::class => 'adapt',
        EnsureDashboardCredential::class => 'adapt',
        VerifyHmacSignature::class => 'deferred — resolved by P5 transport consolidation',
        EnsureStandaloneAuthority::class => 'out of scope — authority-mode gate, not an account-bound ingress',
    ];
}

it('derives exactly the corrected AC17 manifest including class-bound middleware', function (): void {
    $manifest = correctedManagedIngressManifest();
    $discovered = ManagedIngressManifest::discover(dirname(__DIR__).'/src');
    $expected = array_keys($manifest);
    sort($expected);

    expect(ManagedIngressManifest::unexpected($discovered, $manifest))->toBe([])
        ->and(ManagedIngressManifest::missing($discovered, $manifest))->toBe([])
        ->and($discovered)->toBe($expected)
        ->and(array_count_values($manifest))->toBe([
            'adapt' => 9,
            'deferred — resolved by P5 transport consolidation' => 5,
            'out of scope — authority-mode gate, not an account-bound ingress' => 1,
        ]);
});

it('reports a deliberately ungated fixture authenticator as unprotected', function (): void {
    $discovered = ManagedIngressManifest::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures'],
    );

    expect(ManagedIngressManifest::unexpected($discovered, correctedManagedIngressManifest()))
        ->toBe([UnguardedCredentialAuthenticator::class]);
});
