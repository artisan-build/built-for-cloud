<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ReelLikeDeclaration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, ContractAssertions::class);

// Locked AC 1: the conformance suite proves mint/list/revoke produce
// identical outcomes via CLI --local and via HTTP — and the package runs
// the very suite consuming apps run in CI.

it('passes the transport-parity suite under the default declaration, with zero Cloud dependency', function (): void {
    Process::fake();

    $this->assertBuiltForCloudTransportParityContract();

    Process::assertNothingRan();
});

it('passes the transport-parity suite under a declaration with unsupported fields', function (): void {
    app()->bind(CredentialDeclaration::class, ReelLikeDeclaration::class);

    $this->assertBuiltForCloudTransportParityContract();
});

it('asserts refusal parity when the declaration denies the issue verb', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return $verb !== CredentialVerb::Issue;
        }
    });

    $this->assertBuiltForCloudTransportParityContract();

    expect(Credential::query()->count())->toBe(0);
});
