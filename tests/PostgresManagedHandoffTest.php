<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

function availableManagedAuthorityPort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

    if ($socket === false) {
        throw new RuntimeException('Could not reserve a managed authority port: '.$errorNumber.' '.$error);
    }

    $address = stream_socket_get_name($socket, false);
    fclose($socket);

    if (! is_string($address) || ! str_contains($address, ':')) {
        throw new RuntimeException('Could not identify the managed authority port.');
    }

    return (int) substr(strrchr($address, ':'), 1);
}

it('lets exactly one concurrent callback claim the BfC correlation and reach a replay-permissive authority', function (): void {
    $port = availableManagedAuthorityPort();
    $baseUrl = 'https://127.0.0.1:'.$port;
    $clientSecret = bin2hex(random_bytes(32));
    $runDirectory = sys_get_temp_dir().'/bfc-p3a-postgres-'.bin2hex(random_bytes(8));
    $certificate = $runDirectory.'/authority.pem';
    $status = $runDirectory.'/status.json';
    mkdir($runDirectory, 0700);
    $authority = new Process([
        PHP_BINARY,
        __DIR__.'/Live/managed-authority.php',
        (string) $port,
        $certificate,
        'https://callback.example.test',
        $status,
    ], null, [
        'BFC_MANAGED_FIXTURE_CLIENT_SECRET' => $clientSecret,
        'BFC_MANAGED_FIXTURE_APP_KEY' => base64_encode(random_bytes(32)),
        'BFC_MANAGED_CLIENT_APP_KEY' => base64_encode(random_bytes(32)),
    ]);
    $authority->setTimeout(null);
    $authority->start();
    $workers = [];

    try {
        expect($authority->waitUntil(
            static fn (string $type, string $output): bool => str_contains($output, 'READY'),
        ))->toBeTrue();
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'mode' => 'managed',
            'generation' => 7,
            'issuer' => 'https://live-issuer.example.test',
            'connection_id' => 'live-connection',
            'organization_id' => 'live-organization',
            'installation_id' => 'live-installation',
            'authority_base_url' => $baseUrl,
        ]);
        config([
            'built-for-cloud.managed.client_secret' => $clientSecret,
            'built-for-cloud.managed.ca_bundle' => $certificate,
        ]);
        Http::allowStrayRequests();
        $entry = $this->get('/bfc/managed/login');
        $entry->assertRedirect();
        parse_str((string) parse_url((string) $entry->headers->get('Location'), PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;
        $sessionNonce = session('bfc.managed_session_nonce');
        expect($state)->toBeString()->toHaveLength(43)
            ->and($sessionNonce)->toBeString()->toHaveLength(43);

        $main = $this->postgresLaneConnection();
        $main->beginTransaction();
        $main->table('bfc_managed_handoffs')->where('state_hash', hash('sha256', $state))->lockForUpdate()->first();

        foreach (range(1, 5) as $worker) {
            $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-handoff-claim-worker.php']);
            $process->setInput(json_encode([
                'worker' => $worker,
                'state' => $state,
                'session_nonce' => $sessionNonce,
                'code' => 'valid-worker-code-'.$worker,
                'client_secret' => $clientSecret,
                'ca_bundle' => $certificate,
            ], JSON_THROW_ON_ERROR));
            $process->start();
            $workers[] = $process;
        }

        $allBlocked = false;

        foreach (range(1, 5000) as $attempt) {
            foreach ($workers as $process) {
                if (! $process->isRunning()) {
                    throw new RuntimeException(
                        'A callback worker exited before the release: '.$process->getOutput().$process->getErrorOutput(),
                    );
                }
            }

            $active = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name like 'bfc-p3a-callback-worker-%'
                  and state = 'active'
                  and query like '%bfc_managed_handoffs%'
                SQL);

            if ($active === count($workers)) {
                $allBlocked = true;
                break;
            }
        }

        expect($allBlocked)->toBeTrue();
        $main->commit();
        $results = [];

        foreach ($workers as $process) {
            $process->wait();
            expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());
            $results[] = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        }

        $authorityStatus = json_decode((string) file_get_contents($status), true, flags: JSON_THROW_ON_ERROR);
        expect(array_filter($results, static fn (array $result): bool => $result['exchange_reached']))->toHaveCount(1)
            ->and(array_unique(array_column($results, 'code_hash')))->toHaveCount(5)
            ->and(DB::table('bfc_managed_handoffs')->whereNotNull('consumed_at')->count())->toBe(1)
            ->and($authorityStatus['exchange_count'])->toBe(1);

        Http::withToken($clientSecret)
            ->withHeaders(['Bfc-Contract-Version' => 'managed-auth-v1'])
            ->withOptions(['verify' => $certificate])
            ->post($baseUrl.'/managed-auth/v1/handoffs/'.rawurlencode($state).'/exchange', [
                'connection_id' => 'live-connection',
                'installation_id' => 'live-installation',
                'code' => 'positive-control-replay-code',
            ])
            ->throw();
        $positiveControlStatus = json_decode((string) file_get_contents($status), true, flags: JSON_THROW_ON_ERROR);
        expect($positiveControlStatus['exchange_count'])->toBe(2);
    } finally {
        foreach ($workers as $process) {
            if ($process->isRunning()) {
                $process->stop();
            }
        }

        if (isset($main) && $main->transactionLevel() > 0) {
            $main->rollBack();
        }

        if ($authority->isRunning()) {
            $authority->stop();
        }

        @unlink($certificate);
        @unlink($status);
        @unlink($status.'.keypipe');
        @rmdir($runDirectory);
    }
});
