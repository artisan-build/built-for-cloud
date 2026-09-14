<?php

declare(strict_types=1);

use App\Support\P6LiveManagedUser;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

require_once __DIR__.'/Live/P6LiveManagedUser.php';

uses(RefreshDatabase::class);

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

it('persists a bound stale managed user that enters the authority refresh path', function (): void {
    CarbonImmutable::setTestNow('2026-09-15T12:00:00+00:00');
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://p6-authority.test',
        'connection_id' => 'p6-connection',
        'organization_id' => 'p6-organization',
        'installation_id' => 'p6-installation',
        'authority_base_url' => 'https://p6-authority.test',
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
    ]);
    config(['built-for-cloud.managed.client_secret' => 'p6-fixture-client-secret']);
    $authority = new ManagedAuthorityFixture(
        'https://p6-authority.test',
        'p6-fixture-client-secret',
        'https://p6-authority.test',
        'p6-connection',
        'p6-organization',
        'p6-installation',
        7,
    );
    Http::fake(fn (Request $request): mixed => $authority->respond($request));

    $user = P6LiveManagedUser::create()->fresh();
    $staleAt = CarbonImmutable::parse('2026-09-15T11:50:00+00:00');

    expect($user->scalpels_issuer)->toBe('https://p6-authority.test')
        ->and($user->scalpels_connection_id)->toBe('p6-connection')
        ->and($user->scalpels_id)->toBe('p6-managed-subject')
        ->and($user->membership_confirmed_at?->toAtomString())->toBe($staleAt->toAtomString())
        ->and($user->membership_checked_at?->toAtomString())->toBe($staleAt->toAtomString())
        ->and($user->membership_response_at?->toAtomString())->toBe($staleAt->toAtomString())
        ->and($user->managed_membership_status)->toBe('active')
        ->and($user->managed_membership_role)->toBe('member')
        ->and($user->managed_membership_generation)->toBe(7)
        ->and($user->managed_membership_roster_version)->toBe(1)
        ->and($user->managed_membership_response_sequence)->toBe(1)
        ->and(CarbonImmutable::now()->diffInSeconds($user->membership_confirmed_at, true))->toBe(600.0)
        ->and(app(ManagedFreshness::class)->allows($user))->toBeTrue()
        ->and(array_column($authority->calls, 'path'))->toBe(['/managed-auth/v1/memberships/confirm']);
});
