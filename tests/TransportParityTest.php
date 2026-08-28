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

it('does not read a subject-conditional declaration as transport divergence — both legs ask the identical question', function (): void {
    // This declaration keys its issue answer on the SUBJECT REF: it denies
    // any ref naming a transport. Under the old per-leg refs
    // (parity-cli-* / parity-http-*) it would deny exactly one leg and the
    // suite would report a false divergence; with like-for-like refs both
    // legs carry the same ref and get the same answer.
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
            if ($verb !== CredentialVerb::Issue || $subject === null) {
                return true;
            }

            return ! str_contains($subject->ref, 'cli') && ! str_contains($subject->ref, 'http');
        }
    });

    $this->assertBuiltForCloudTransportParityContract();

    // The suite's own refs name no transport, so the conditional matrix
    // allowed both legs and real rows were minted and revoked.
    expect(Credential::query()->count())->toBeGreaterThan(0);
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

it('asserts rotate refusal parity when the declaration denies rotate but allows issue', function (): void {
    // Denying only `rotate` drives the suite down the ROTATE leg's own
    // refusal branch: mint/list/basic/revoke run for real, and the rotate
    // comparison must observe both transports refusing identically with
    // neither target stamped.
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
            return $verb !== CredentialVerb::Rotate;
        }
    });

    $this->assertBuiltForCloudTransportParityContract();

    // Rows were minted (issue is allowed) and none was ever rotated.
    expect(Credential::query()->count())->toBeGreaterThan(0)
        ->and(Credential::query()->whereNotNull('rotated_at')->count())->toBe(0);
});
