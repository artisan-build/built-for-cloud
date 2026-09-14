<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(PostgresLane::class)->group('pgsql');

const BFC_SIGNING_ROOT_POSTGRES_LOCK_TIMEOUT = '750ms';

function expectSigningRootPostgresLockRefusal(?Throwable $failure, string $message): void
{
    expect($failure)->toBeInstanceOf(QueryException::class, $message)
        ->and((string) $failure?->getCode())->toBe('55P03');
}

/** @return list<Credential> */
function currentPostgresSigningRoots(): array
{
    return SigningRootMac::currentCandidates()->orderBy('id')->get()->all();
}

function runSigningRootOnConnection(string $connection, callable $action): mixed
{
    $previous = (string) config('database.default');
    config(['database.default' => $connection]);

    try {
        return $action();
    } finally {
        config(['database.default' => $previous]);
    }
}

it('serializes concurrent provisioning on the installation authority row and commits one root', function (): void {
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();
    $main->beginTransaction();
    $winner = app(SigningRootLifecycle::class)->provision();

    $probe->statement("set lock_timeout = '".BFC_SIGNING_ROOT_POSTGRES_LOCK_TIMEOUT."'");
    $failure = null;

    try {
        runSigningRootOnConnection('pgsql_testing_probe', fn () => app(SigningRootLifecycle::class)->provision());
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $probe->statement('set lock_timeout = default');
        $main->commit();
    }

    expectSigningRootPostgresLockRefusal(
        $failure,
        'A second provision completed while the first transaction owned the installation authority row.',
    );
    expect(currentPostgresSigningRoots())->toHaveCount(1)
        ->and(currentPostgresSigningRoots()[0]->id)->toBe($winner->summary->id)
        ->and(Credential::query()->where('purpose', CredentialPurpose::SigningRoot->value)->count())->toBe(1);
});

it('keeps the old root signing until a serialized rotation commits, then exposes only the replacement', function (): void {
    $old = app(SigningRootLifecycle::class)->provision();
    $before = app(SigningRootMac::class)->mac('postgres rotation bytes');
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();
    $main->beginTransaction();
    $winner = app(SigningRootLifecycle::class)->rotate($old->summary->id, false);

    $probe->statement("set lock_timeout = '".BFC_SIGNING_ROOT_POSTGRES_LOCK_TIMEOUT."'");
    $probeFailure = null;

    try {
        $during = runSigningRootOnConnection(
            'pgsql_testing_probe',
            fn () => app(SigningRootMac::class)->mac('postgres rotation bytes'),
        );

        expect($during->keyId)->toBe($old->summary->id)
            ->and(runSigningRootOnConnection(
                'pgsql_testing_probe',
                fn () => app(SigningRootMac::class)->verify($before->keyId, 'postgres rotation bytes', $before->lowercaseHexMac),
            ))->toBeTrue();

        runSigningRootOnConnection(
            'pgsql_testing_probe',
            fn () => app(SigningRootLifecycle::class)->rotate($old->summary->id, false),
        );
    } catch (Throwable $exception) {
        $probeFailure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $probe->statement('set lock_timeout = default');
        $main->commit();
    }

    expectSigningRootPostgresLockRefusal(
        $probeFailure,
        'A second rotation completed while the first transaction owned the installation authority row.',
    );

    $after = app(SigningRootMac::class)->mac('postgres rotation bytes');
    expect($after->keyId)->toBe($winner->mint->summary->id)
        ->and($after->keyId)->not->toBe($old->summary->id)
        ->and(app(SigningRootMac::class)->verify($before->keyId, 'postgres rotation bytes', $before->lowercaseHexMac))->toBeTrue()
        ->and(currentPostgresSigningRoots())->toHaveCount(1)
        ->and(currentPostgresSigningRoots()[0]->id)->toBe($winner->mint->summary->id);
});

it('rolls back invalid multiple and foreign current-root rotation states without mutation', function (string $subjectRef): void {
    $root = app(SigningRootLifecycle::class)->provision();
    $encrypted = app(HmacKeyring::class)->encrypt(bin2hex(random_bytes(32)));

    DB::table('credentials')->insert([
        'id' => (string) Str::uuid(),
        'kind' => CredentialKind::Hmac->value,
        'purpose' => CredentialPurpose::SigningRoot->value,
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => $subjectRef,
        'abilities' => null,
        'status' => CredentialStatus::Active->value,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $before = DB::table('credentials')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all();
    $auditCount = DB::table('credential_audit_events')->count();

    expect(fn () => app(SigningRootLifecycle::class)->rotate($root->summary->id, false))
        ->toThrow(SigningRootRefused::class)
        ->and(DB::transactionLevel())->toBe(0)
        ->and(DB::table('credentials')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all())->toBe($before)
        ->and(DB::table('credential_audit_events')->count())->toBe($auditCount);
})->with([
    'multiple exact current roots' => SigningRootMac::SUBJECT_REF,
    'foreign current root mixed into the reserved set' => 'foreign-signing-root',
]);
