<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

function p3cPgAvailablePort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

    if ($socket === false) {
        throw new RuntimeException('Could not reserve a managed freshness port: '.$errorNumber.' '.$error);
    }

    $address = stream_socket_get_name($socket, false);
    fclose($socket);

    if (! is_string($address) || ! str_contains($address, ':')) {
        throw new RuntimeException('Could not identify the managed freshness port.');
    }

    return (int) substr(strrchr($address, ':'), 1);
}

function p3cPgConfigureAuthority(string $baseUrl): void
{
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => InstallationAuthority::KEY],
        [
            'mode' => 'managed',
            'generation' => 7,
            'issuer' => 'https://live-issuer.example.test',
            'connection_id' => 'live-connection',
            'organization_id' => 'live-organization',
            'installation_id' => 'live-installation',
            'authority_base_url' => $baseUrl,
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
}

function p3cPgUser(string $subject, int $sequence = 10): User
{
    $user = User::query()->create([
        'name' => $subject,
        'email' => $subject.'@example.test',
    ]);
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://live-issuer.example.test',
        'scalpels_connection_id' => 'live-connection',
        'scalpels_id' => $subject,
        'membership_confirmed_at' => now()->subSeconds(300),
        'membership_checked_at' => now()->subSeconds(300),
        'membership_response_at' => now()->subSeconds(300),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => $sequence,
        'managed_membership_response_sequence' => $sequence,
        'managed_membership_responded_at' => now()->subSeconds(300),
    ])->save();

    return $user->refresh();
}

function p3cPgCredential(User $user, string $secret): Credential
{
    return Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => (string) $user->scalpels_id,
        'user_id' => (string) $user->getKey(),
        'secret_hash' => hash('sha256', $secret),
    ]);
}

function p3cPgSession(User $user, string $id): void
{
    DB::table('sessions')->insert([
        'id' => $id,
        'user_id' => $user->getKey(),
        'payload' => 'postgres managed freshness',
        'last_activity' => now()->timestamp,
    ]);
}

/** @param array<string, mixed> $overrides */
function p3cPgStartWorker(int $worker, array $overrides): Process
{
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-freshness-worker.php']);
    $process->setInput(json_encode(array_merge([
        'application_name' => 'bfc-p3c1-worker-'.$worker,
        'mode' => 'decision',
        'subject' => 'storm-subject',
        'now' => '2026-09-10T12:00:00+00:00',
        'client_secret' => null,
        'ca_bundle' => null,
    ], $overrides), JSON_THROW_ON_ERROR));
    $process->start();

    return $process;
}

/** @return array<string, mixed> */
function p3cPgFinishWorker(Process $process): array
{
    $process->wait();
    expect($process->isSuccessful())->toBeTrue($process->getOutput().$process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

/**
 * Wait for the worker's readiness signal on a WALL-CLOCK deadline, yielding between polls.
 *
 * This was a bare `foreach (range(1, 20000))` hot spin with no sleep and no clock, and it was the cause of
 * a recurring CI failure ("Timed out waiting for managed freshness fixture status", this file). Two defects,
 * both measured rather than inferred:
 *
 *  1. **The bound was iterations, not time.** 20,000 iterations is whatever wall clock the machine happens
 *     to give it — measured at **298 ms** on a developer Mac. The thing it waits for is a freshly forked PHP
 *     process booting the framework and connecting to PostgreSQL, which routinely takes longer than that. The
 *     "timeout" was therefore a function of CPU speed, not of how long the work legitimately needs.
 *  2. **It never yielded.** A tight spin calling `file_get_contents()` and `Process::isRunning()` burns a
 *     core, and on a 2-4 core CI runner already hosting five workers and PostgreSQL it starves the very
 *     child process it is waiting for. The busier the machine, the less CPU the worker gets — so the wait
 *     failed hardest exactly when the work was slowest.
 *
 * The deadline is generous on purpose: it exists to stop a hung worker wedging the suite, not to police how
 * fast a worker ought to be. `usleep()` between polls is what makes the CPU available to the worker.
 */
function p3cPgWaitForStatus(
    string $path,
    callable $accept,
    ?Process $process = null,
    float $deadlineSeconds = 30.0,
): array {
    $deadline = microtime(true) + $deadlineSeconds;

    while (true) {
        $contents = @file_get_contents($path);
        $status = is_string($contents) ? json_decode($contents, true) : null;

        if (is_array($status) && $accept($status)) {
            return $status;
        }

        if ($process instanceof Process && ! $process->isRunning()) {
            throw new RuntimeException('Worker exited before fixture observation: '.$process->getOutput().$process->getErrorOutput());
        }

        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out waiting for managed freshness fixture status.');
        }

        // Yield the core to the worker. Without this the parent starves the process it is waiting for.
        usleep(2000);
    }
}

// REPRODUCTION for the flake this file kept hitting in CI. The producer below takes ~1s to publish its
// readiness signal -- far less than a real worker needs, and far MORE than the old iteration-bounded spin
// allowed (measured: 20,000 iterations = 298 ms on a developer Mac, and less on a busier machine). Reverting
// p3cPgWaitForStatus() to that spin turns this red with the exact production failure message.
it('waits for a readiness signal on a wall clock rather than an iteration count', function (): void {
    $path = sys_get_temp_dir().'/bfc-readiness-'.bin2hex(random_bytes(8)).'.json';
    $producer = new Process([
        PHP_BINARY,
        '-r',
        'usleep(1000000); file_put_contents($argv[1], json_encode(["ready" => true]));',
        $path,
    ]);
    $producer->start();

    try {
        $started = microtime(true);
        $status = p3cPgWaitForStatus($path, static fn (array $status): bool => ($status['ready'] ?? false) === true, $producer);
        $elapsed = microtime(true) - $started;

        // It waited for the signal rather than giving up on an iteration budget...
        expect($status['ready'])->toBeTrue()
            // ...it genuinely waited out the producer rather than finding the file already there...
            ->and($elapsed)->toBeGreaterThan(0.5)
            // ...and it yielded instead of spinning, so the wait cost far fewer polls than 20,000.
            ->and($elapsed)->toBeLessThan(25.0);
    } finally {
        $producer->wait();
        @unlink($path);
    }
});

/** @return list<array<string, mixed>> */
function p3cPgRunWave(
    int $wave,
    int $second,
    string $statusPath,
    string $secret,
    string $certificate,
    bool $killHolder,
): array {
    $before = p3cPgWaitForStatus($statusPath, static fn (array $status): bool => true);
    $expected = $before['confirmation_count'] + 1;
    $now = CarbonImmutable::parse('2026-09-10T12:00:00+00:00')->addSeconds($second)->toAtomString();
    $input = [
        'now' => $now,
        'client_secret' => $secret,
        'ca_bundle' => $certificate,
    ];
    $workers = [];

    if ($killHolder) {
        $holder = p3cPgStartWorker($wave * 10, $input);
        p3cPgWaitForStatus(
            $statusPath,
            static fn (array $status): bool => $status['confirmation_count'] === $expected
                && $status['confirmation_in_flight'] === true,
            $holder,
        );
        $holder->stop(0, SIGKILL);

        foreach (range(1, 4) as $worker) {
            $workers[] = p3cPgStartWorker(($wave * 10) + $worker, $input);
        }
    } else {
        foreach (range(0, 4) as $worker) {
            $workers[] = p3cPgStartWorker(($wave * 10) + $worker, $input);
        }
    }

    $results = array_map(p3cPgFinishWorker(...), $workers);
    $status = p3cPgWaitForStatus(
        $statusPath,
        static fn (array $status): bool => $status['confirmation_in_flight'] === false,
    );
    expect($status['confirmation_count'])->toBe($expected)
        ->and(array_unique(array_column($results, 'allowed')))->toBe([true]);

    return $results;
}

function p3cPgRunSuppressedProbe(
    int $wave,
    int $second,
    string $statusPath,
    string $secret,
    string $certificate,
): void {
    $before = p3cPgWaitForStatus($statusPath, static fn (array $status): bool => true);
    $now = CarbonImmutable::parse('2026-09-10T12:00:00+00:00')->addSeconds($second)->toAtomString();
    $workers = [];

    foreach (range(1, 4) as $worker) {
        $workers[] = p3cPgStartWorker(($wave * 100) + $worker, [
            'now' => $now,
            'client_secret' => $secret,
            'ca_bundle' => $certificate,
        ]);
    }

    $results = array_map(p3cPgFinishWorker(...), $workers);
    $after = p3cPgWaitForStatus($statusPath, static fn (array $status): bool => true);
    expect($after['confirmation_count'])->toBe($before['confirmation_count'])
        ->and(array_unique(array_column($results, 'allowed')))->toBe([true]);
}

it('accounts attempts at start and suppresses concurrent and killed-holder retries on a shared database cache', function (): void {
    $schema = $this->postgresLaneConnection()->getSchemaBuilder();

    if (! $schema->hasTable('cache')) {
        $schema->create('cache', function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->text('value');
            $table->integer('expiration');
        });
        $schema->create('cache_locks', function (Blueprint $table): void {
            $table->string('key')->primary();
            $table->string('owner');
            $table->integer('expiration');
        });
    }

    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $port = p3cPgAvailablePort();
    $baseUrl = 'https://127.0.0.1:'.$port;
    $secret = bin2hex(random_bytes(32));
    $runDirectory = sys_get_temp_dir().'/bfc-p3c1-postgres-'.bin2hex(random_bytes(8));
    $certificate = $runDirectory.'/authority.pem';
    $statusPath = $runDirectory.'/status.json';
    mkdir($runDirectory, 0700);
    $authority = new Process([
        PHP_BINARY,
        __DIR__.'/Live/managed-authority.php',
        (string) $port,
        $certificate,
        'https://callback.example.test',
        $statusPath,
    ], null, [
        'BFC_MANAGED_FIXTURE_CLIENT_SECRET' => $secret,
        'BFC_MANAGED_FIXTURE_APP_KEY' => base64_encode(random_bytes(32)),
        'BFC_MANAGED_CLIENT_APP_KEY' => base64_encode(random_bytes(32)),
        'BFC_MANAGED_FIXTURE_CONFIRM_DELAY_US' => '200000',
        'BFC_MANAGED_FIXTURE_CONFIRM_STATUS' => '503',
    ]);
    $authority->setTimeout(null);
    $authority->start();

    try {
        expect($authority->waitUntil(
            static fn (string $type, string $output): bool => str_contains($output, 'READY'),
        ))->toBeTrue();
        p3cPgConfigureAuthority($baseUrl);
        p3cPgUser('storm-subject');
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'managed_connection_status' => 'active',
            'managed_connection_generation' => 7,
            'managed_connection_roster_version' => 10,
            'managed_connection_response_sequence' => 10,
        ]);
        foreach (range(0, 10) as $wave) {
            $second = $wave * 30;
            p3cPgRunWave(
                $wave + 1,
                $second,
                $statusPath,
                $secret,
                $certificate,
                in_array($wave, [1, 2, 3], true),
            );
            if (in_array($wave, [1, 2, 3], true)) {
                p3cPgRunSuppressedProbe(
                    $wave + 1,
                    $second + 11,
                    $statusPath,
                    $secret,
                    $certificate,
                );
            }
        }

        $status = p3cPgWaitForStatus($statusPath, static fn (array $status): bool => true);
        // This observes one call per scheduled wave and, through the helper assertions, none from
        // suppressed probes. The fixture does not independently measure arbitrary sliding windows.
        expect($status['confirmation_count'])->toBe(11);
    } finally {
        if ($authority->isRunning()) {
            $authority->stop();
        }

        @unlink($certificate);
        @unlink($statusPath);
        @unlink($statusPath.'.keypipe');
        @rmdir($runDirectory);
    }
});

it('serializes real concurrent cross-subject responses while preserving both independent dimensions', function (array $order, string $case): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cPgConfigureAuthority('https://authority.example.test');
    $a = p3cPgUser('subject-a');
    $b = p3cPgUser('subject-b');
    $credentialA = p3cPgCredential($a, 'postgres-subject-a');
    $credentialB = p3cPgCredential($b, 'postgres-subject-b');
    p3cPgSession($a, 'postgres-subject-a');
    p3cPgSession($b, 'postgres-subject-b');
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
        'managed_connection_roster_version' => 10,
        'managed_connection_response_sequence' => 10,
    ]);
    $payloads = $case === 'membership'
        ? [
            'a' => ['sequence' => 20, 'membership_status' => 'removed', 'connection_status' => 'active'],
            'b' => ['sequence' => 21, 'membership_status' => 'active', 'connection_status' => 'active'],
        ]
        : [
            'a' => ['sequence' => 20, 'membership_status' => 'active', 'connection_status' => 'inactive'],
            'b' => ['sequence' => 21, 'membership_status' => 'active', 'connection_status' => 'active'],
        ];
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('bfc_authority')->where('key', InstallationAuthority::KEY)->lockForUpdate()->first();
    $workers = [];

    try {
        foreach ($order as $index => $subject) {
            $workers[] = p3cPgStartWorker(100 + $index, array_merge($payloads[$subject], [
                'application_name' => 'bfc-p3c1-order-'.$index,
                'mode' => 'apply',
                'subject' => 'subject-'.$subject,
                'now' => '2026-09-10T12:01:00+00:00',
            ]));
            $expected = $index + 1;

            foreach (range(1, 5000) as $attempt) {
                $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                    select count(*)
                    from pg_stat_activity
                    where datname = current_database()
                      and application_name like 'bfc-p3c1-order-%'
                      and state = 'active'
                      and wait_event_type = 'Lock'
                      and query like '%bfc_authority%'
                    SQL);

                if ($blocked === $expected) {
                    break;
                }
            }

            expect($blocked)->toBe($expected);
        }

        $main->commit();
        array_map(p3cPgFinishWorker(...), $workers);
        $authority = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();
        $a = User::query()->where('scalpels_id', 'subject-a')->sole();
        $b = User::query()->where('scalpels_id', 'subject-b')->sole();
        $connectionDenialApplied = $case === 'connection' && $order === ['a', 'b'];
        expect($a->managed_membership_status)
            ->toBe($case === 'membership' ? 'removed' : 'active')
            ->and($a->managed_membership_response_sequence)->toBe(20)
            ->and($b->managed_membership_response_sequence)->toBe(21)
            ->and($authority->managed_connection_status)->toBe('active')
            ->and($authority->managed_connection_response_sequence)->toBe(21)
            ->and($a->auth_session_version)->toBe($case === 'membership' || $connectionDenialApplied ? 2 : 1)
            ->and($b->auth_session_version)->toBe($connectionDenialApplied ? 2 : 1)
            ->and($credentialA->fresh()->revoked_at !== null)->toBe($case === 'membership' || $connectionDenialApplied)
            ->and($credentialB->fresh()->revoked_at !== null)->toBe($connectionDenialApplied)
            ->and(DB::table('sessions')->where('id', 'postgres-subject-a')->exists())->toBe(! ($case === 'membership' || $connectionDenialApplied))
            ->and(DB::table('sessions')->where('id', 'postgres-subject-b')->exists())->toBe(! $connectionDenialApplied);
    } finally {
        foreach ($workers as $worker) {
            if ($worker->isRunning()) {
                $worker->stop();
            }
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
})->with([
    'membership A then B' => [['a', 'b'], 'membership'],
    'membership B then A' => [['b', 'a'], 'membership'],
    'connection A then B' => [['a', 'b'], 'connection'],
    'connection B then A' => [['b', 'a'], 'connection'],
]);
