<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCurrentOwnerCredential;
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
        ConsoleGuard::class => 'wontfix — not account-bound; residue 1',
        BasicAuthenticator::class => 'adapt',
        BearerAuthenticator::class => 'adapt',
        CredentialResolver::class => 'adapt',
        EnsureUserIsAuthenticated::class => 'adapt',
        EnsureUserIsAdmin::class => 'adapt',
        EnsureConsoleSession::class => 'wontfix — not account-bound; residue 1',
        EnsureContractMajor::class => 'out of scope — contract admission gate, not an account-bound ingress',
        AuthenticateMcp::class => 'cleared — store bearer converged; assertion wontfix — not account-bound; residue 1',
        EnsureCredentialAdmin::class => 'adapt',
        EnsureCurrentOwnerCredential::class => 'adapt',
        EnsureCredentialAbility::class => 'adapt',
        EnsureDashboardCredential::class => 'adapt',
        VerifyHmacSignature::class => 'cleared — managed account containment added',
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
        ->and(array_filter(
            $manifest,
            static fn (string $disposition): bool => str_contains($disposition, 'deferred'),
        ))->toBe([])
        ->and(array_count_values($manifest))->toBe([
            'adapt' => 10,
            'wontfix — not account-bound; residue 1' => 2,
            'out of scope — contract admission gate, not an account-bound ingress' => 1,
            'cleared — store bearer converged; assertion wontfix — not account-bound; residue 1' => 1,
            'cleared — managed account containment added' => 1,
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
