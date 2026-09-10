<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\InstallationAuthority;
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
    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

/** @return array<string, mixed> */
function p3cPgWaitForStatus(string $path, callable $accept, ?Process $process = null): array
{
    foreach (range(1, 20000) as $attempt) {
        $contents = @file_get_contents($path);
        $status = is_string($contents) ? json_decode($contents, true) : null;

        if (is_array($status) && $accept($status)) {
            return $status;
        }

        if ($process instanceof Process && ! $process->isRunning()) {
            throw new RuntimeException('Worker exited before fixture observation: '.$process->getOutput().$process->getErrorOutput());
        }
    }

    throw new RuntimeException('Timed out waiting for managed freshness fixture status.');
}

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

it('accounts attempts at start and keeps repeated multi-process waves within the half-open bound on a shared database cache', function (): void {
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
        $starts = [];

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
            $starts[] = $second;

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
        expect($status['confirmation_count'])->toBe(11)
            ->and(count(array_filter($starts, static fn (int $start): bool => $start >= 0 && $start < 300)))->toBe(10);

        foreach ($starts as $windowStart) {
            expect(count(array_filter(
                $starts,
                static fn (int $start): bool => $start >= $windowStart && $start < $windowStart + 300,
            )))->toBeLessThanOrEqual(10);
        }
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
    p3cPgUser('subject-a');
    p3cPgUser('subject-b');
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
        expect(User::query()->where('scalpels_id', 'subject-a')->sole()->managed_membership_status)
            ->toBe($case === 'membership' ? 'removed' : 'active')
            ->and(User::query()->where('scalpels_id', 'subject-a')->sole()->managed_membership_response_sequence)->toBe(20)
            ->and(User::query()->where('scalpels_id', 'subject-b')->sole()->managed_membership_response_sequence)->toBe(21)
            ->and($authority->managed_connection_status)->toBe('active')
            ->and($authority->managed_connection_response_sequence)->toBe(21);
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
