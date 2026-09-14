<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\Assertion;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionPurpose;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(PostgresLane::class)->group('pgsql');

it('runs and records the representative supported PostgreSQL matrix', function (): void {
    $primary = $this->postgresLaneConnection();
    $secondary = $this->postgresLaneProbe();
    expect($primary->scalar('select current_database()'))->toBe($secondary->scalar('select current_database()'))
        ->and($primary->scalar('select pg_backend_pid()'))->not->toBe($secondary->scalar('select pg_backend_pid()'))
        ->and($primary->scalar('show lock_timeout'))->toBe('750ms')
        ->and($secondary->scalar('show lock_timeout'))->toBe('750ms');

    User::query()->create(['name' => 'Unique A', 'email' => 'Postgres-Matrix@example.test']);
    expect(fn () => User::query()->create(['name' => 'Unique B', 'email' => 'postgres-matrix@example.test']))
        ->toThrow(QueryException::class);
    $this->recordPostgresCase('uniqueness');

    $locked = User::query()->create(['name' => 'Lock Target', 'email' => 'lock-target@example.test']);
    $primary->beginTransaction();
    $primary->table('users')->where('id', $locked->getKey())->lockForUpdate()->first();
    $secondary->beginTransaction();
    $lockFailure = null;
    try {
        $secondary->table('users')->where('id', $locked->getKey())->update(['name' => 'Blocked']);
    } catch (Throwable $exception) {
        $lockFailure = $exception;
    } finally {
        $secondary->rollBack();
        $primary->rollBack();
    }
    expect($lockFailure)->toBeInstanceOf(QueryException::class)
        ->and((string) $lockFailure?->getCode())->toBe('55P03');
    $this->recordPostgresCase('row_lock');

    $transition = [
        'initiated_by_user_id' => 'matrix-user',
        'direction' => 'adopt',
        'status' => 'preparing',
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'matrix-connection',
        'organization_id' => 'matrix-organization',
        'installation_id' => 'matrix-installation',
        'authority_base_url' => 'https://authority.example.test',
        'client_credential_reference' => 'built-for-cloud.managed.client_secret',
        'mode_before' => 'standalone',
        'mode_after' => 'managed',
        'generation_before' => 1,
        'generation_after' => 2,
        'transition_request_id' => str_repeat('a', 43),
        'prepare_request_body' => '{}',
        'prepare_body_digest' => hash('sha256', '{}'),
    ];
    ManagedTransition::createActive($transition);
    expect(fn () => ManagedTransition::createActive([
        ...$transition,
        'id' => (string) Str::uuid(),
        'transition_request_id' => str_repeat('b', 43),
    ]))->toThrow(ManagedAuthRefused::class, 'transition_in_progress');
    $this->recordPostgresCase('managed_transition');

    $now = CarbonImmutable::now();
    $assertion = Assertion::fromVerifiedClaims(
        'https://issuer.example.test',
        'matrix-subject',
        'Matrix Subject',
        ConsoleRole::Admin,
        null,
        'matrix-installation',
        $now,
        $now->addMinute(),
        'matrix-key',
        'matrix-mint',
        purpose: AssertionPurpose::Mcp,
    );
    DB::transaction(static fn () => AssertionBurn::burn($assertion, $now));
    expect(fn () => DB::transaction(static fn () => AssertionBurn::burn($assertion, $now)))
        ->toThrow(ConsoleEntryRefused::class);
    $this->recordPostgresCase('replay');

    $consumptionSecret = 'p6-purpose-consumption-'.bin2hex(random_bytes(16));
    Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'matrix-consumer',
        'secret_hash' => hash('sha256', $consumptionSecret),
        'status' => CredentialStatus::Active,
    ]);
    $request = Request::create('/matrix-mcp', 'POST', server: [
        'HTTP_AUTHORIZATION' => 'Bearer '.$consumptionSecret,
    ]);
    $response = app(AuthenticateMcp::class)->handle($request, static fn () => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(AuthenticateMcp::REFUSAL_STATUS);
    $this->recordPostgresCase('purpose');
});
