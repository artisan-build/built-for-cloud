<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

const COUNTERS = [
    'authentication_entries',
    'credential_resolver_invocations',
    'replay_store_reads',
    'replay_store_writes',
    'cache_actions',
    'queue_actions',
    'domain_actions',
];

/** @return never */
function failHarness(string $message): void
{
    throw new RuntimeException($message);
}

function requireSame(mixed $expected, mixed $actual, string $label): void
{
    if ($actual !== $expected) {
        failHarness("{$label} did not match its expected value.");
    }
}

/** @return array<string, int> */
function readState(string $path): array
{
    $contents = file_get_contents($path);
    $decoded = is_string($contents) ? json_decode($contents, true) : null;

    if (! is_array($decoded)) {
        failHarness('The live counter state was unreadable.');
    }

    $state = [];

    foreach (COUNTERS as $counter) {
        $value = $decoded[$counter] ?? null;

        if (! is_int($value)) {
            failHarness("The live counter [{$counter}] was absent or invalid.");
        }

        $state[$counter] = $value;
    }

    return $state;
}

/**
 * @param  list<array{0: string, 1: string}>  $headers
 * @return array{status: int, headers: array<string, list<string>>, body: string}
 */
function rawRequest(int $port, string $method, string $path, array $headers = [], string $body = ''): array
{
    $socket = @stream_socket_client(
        "tcp://127.0.0.1:{$port}",
        $errorNumber,
        $error,
        0.4,
        STREAM_CLIENT_CONNECT,
    );

    if (! is_resource($socket)) {
        failHarness('Could not connect to the bounded loopback listener.');
    }

    stream_set_timeout($socket, 3);

    $request = "{$method} {$path} HTTP/1.1\r\n"
        ."Host: 127.0.0.1:{$port}\r\n"
        ."Accept: application/json\r\n"
        ."Connection: close\r\n";

    foreach ($headers as [$name, $value]) {
        $request .= "{$name}: {$value}\r\n";
    }

    $request .= 'Content-Length: '.strlen($body)."\r\n\r\n{$body}";

    $written = 0;
    $length = strlen($request);

    while ($written < $length) {
        $bytes = fwrite($socket, substr($request, $written));

        if ($bytes === false || $bytes === 0) {
            fclose($socket);
            failHarness('The loopback request could not be written completely.');
        }

        $written += $bytes;
    }

    $raw = '';

    while (! feof($socket)) {
        $chunk = fread($socket, 8192);

        if ($chunk === false) {
            fclose($socket);
            failHarness('The loopback response could not be read.');
        }

        $raw .= $chunk;
        $metadata = stream_get_meta_data($socket);

        if (($metadata['timed_out'] ?? false) === true) {
            fclose($socket);
            failHarness('The loopback response exceeded its read deadline.');
        }
    }

    fclose($socket);

    [$head, $responseBody] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
    $lines = explode("\r\n", $head);
    $statusLine = array_shift($lines);

    if (! is_string($statusLine) || preg_match('/^HTTP\/\S+ ([0-9]{3}) /', $statusLine, $matches) !== 1) {
        failHarness('The loopback response had no valid HTTP status line.');
    }

    $responseHeaders = [];

    foreach ($lines as $line) {
        if (! str_contains($line, ':')) {
            continue;
        }

        [$name, $value] = explode(':', $line, 2);
        $responseHeaders[strtolower($name)][] = trim($value);
    }

    return [
        'status' => (int) $matches[1],
        'headers' => $responseHeaders,
        'body' => $responseBody,
    ];
}

/** @param array{status: int, headers: array<string, list<string>>, body: string} $response */
function assertRefusal(array $response, int $status, string $error): void
{
    $expected = json_encode([
        'error' => $error,
        'supported_contract_major' => 2,
    ], JSON_THROW_ON_ERROR);

    requireSame($status, $response['status'], "{$error} status");
    requireSame($expected, $response['body'], "{$error} body");

    $cacheControl = implode(', ', $response['headers']['cache-control'] ?? []);

    if (preg_match('/(?:^|,)\s*no-store\s*(?:,|$)/i', $cacheControl) !== 1) {
        failHarness("{$error} response omitted Cache-Control no-store.");
    }

    if (array_key_exists('retry-after', $response['headers'])) {
        failHarness("{$error} response included Retry-After.");
    }
}

/** @param array{status: int, headers: array<string, list<string>>, body: string} $response */
function observation(array $response, int $contractHeaderFields, ?array $body = null): array
{
    return [
        'request_contract_header_fields' => $contractHeaderFields,
        'response_status' => $response['status'],
        'response_body' => $body,
        'cache_control' => $response['headers']['cache-control'][0] ?? null,
        'retry_after_present' => array_key_exists('retry-after', $response['headers']),
        'verdict' => 'pass',
        'exit_code' => 0,
    ];
}

function runChecked(Process $process, string $label): string
{
    $exitCode = $process->run();

    if ($exitCode !== 0) {
        failHarness("{$label} exited non-zero: {$process->getErrorOutput()}");
    }

    return $process->getOutput();
}

function allocateLoopbackPort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

    if (! is_resource($socket)) {
        failHarness('The OS could not allocate a loopback port.');
    }

    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = is_string($address) ? parse_url('tcp://'.$address, PHP_URL_PORT) : false;

    if (! is_int($port)) {
        failHarness('The OS-allocated loopback port could not be read.');
    }

    return $port;
}

function listenerIdentity(int $pid, int $port, string $root): array
{
    $process = new Process([
        '/usr/sbin/lsof',
        '-nP',
        '-a',
        '-p',
        (string) $pid,
        '-iTCP:'.$port,
        '-sTCP:LISTEN',
        '-Fpcn',
    ], $root);
    $output = runChecked($process, 'listener identity check');

    if (! str_contains($output, "p{$pid}\n") || ! str_contains($output, ":{$port}")) {
        failHarness('The listener identity did not match the spawned process and allocated port.');
    }

    preg_match('/^c(.+)$/m', $output, $command);

    return [
        'pid' => $pid,
        'command' => $command[1] ?? null,
        'address' => "127.0.0.1:{$port}",
        'pid_matches_spawned_process' => true,
        'port_matches_os_allocation' => true,
    ];
}

function listenerAbsent(int $port, string $root): bool
{
    $process = new Process([
        '/usr/sbin/lsof',
        '-nP',
        '-iTCP:'.$port,
        '-sTCP:LISTEN',
        '-t',
    ], $root);
    $process->run();

    return trim($process->getOutput()) === '';
}

$root = dirname(__DIR__, 2);
$stampPath = $argv[1] ?? '';

if ($stampPath === '') {
    fwrite(STDERR, "usage: php tests/Live/run-contract-major-harness.php <stamp-path>\n");
    exit(2);
}

$stampDirectory = dirname($stampPath);

if (! is_dir($stampDirectory) && ! mkdir($stampDirectory, 0777, true) && ! is_dir($stampDirectory)) {
    fwrite(STDERR, "Could not create the stamp directory.\n");
    exit(2);
}

$runDirectory = sys_get_temp_dir().'/bfc-contract-major-'.bin2hex(random_bytes(8));

if (! mkdir($runDirectory, 0700)) {
    fwrite(STDERR, "Could not create the live fixture run directory.\n");
    exit(2);
}

$database = $runDirectory.'/database.sqlite';
$statePath = $runDirectory.'/state.json';
$serverLog = $runDirectory.'/server.log';
$port = allocateLoopbackPort();
$baseEnvironment = getenv();
$baseEnvironment = is_array($baseEnvironment) ? $baseEnvironment : [];
$environment = array_merge($baseEnvironment, [
    'APP_ENV' => 'testing',
    'APP_KEY' => 'base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
    'APP_URL' => "http://127.0.0.1:{$port}",
    'DB_CONNECTION' => 'sqlite',
    'DB_DATABASE' => $database,
    'SESSION_DRIVER' => 'array',
    'CACHE_STORE' => 'array',
    'QUEUE_CONNECTION' => 'sync',
    'MAIL_MAILER' => 'array',
    'BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS' => 'false',
    'BFC_CONTRACT_MAJOR_STATE' => $statePath,
]);

touch($database);

$stamp = [
    'schema' => 'bfc.contract-major.loopback.v1',
    'candidate_sha' => null,
    'runtime' => [
        'php' => PHP_VERSION,
        'laravel' => Application::VERSION,
    ],
    'transport' => [
        'kind' => 'tcp-loopback',
        'port_allocation' => 'stream_socket_server(tcp://127.0.0.1:0)',
        'listener' => null,
        'readiness' => [
            'bounded' => true,
            'sleep_used' => false,
            'verdict' => 'not-run',
        ],
        'teardown' => [
            'bounded' => true,
            'listener_absent' => false,
            'verdict' => 'not-run',
        ],
    ],
    'commands' => [],
    'cases' => [],
    'overall_verdict' => 'fail',
    'exit_code' => 1,
];

$server = null;
$serverOutput = fopen($serverLog, 'wb');

try {
    if (! is_resource($serverOutput)) {
        failHarness('Could not open the bounded server log.');
    }

    $sha = trim(runChecked(new Process(['git', 'rev-parse', 'HEAD'], $root), 'candidate SHA read'));
    $stamp['candidate_sha'] = $sha;

    $migration = new Process([
        $root.'/vendor/bin/testbench',
        'migrate:fresh',
        '--force',
        '--no-interaction',
    ], $root, $environment);
    runChecked($migration, 'live fixture migration');
    $stamp['commands']['migration_exit_code'] = 0;

    $seed = new Process([PHP_BINARY, $root.'/tests/Live/seed-contract-major-harness.php'], $root, $environment);
    $seedOutput = runChecked($seed, 'live fixture seed');
    $seeded = json_decode($seedOutput, true);

    if (! is_array($seeded)
        || ! is_string($seeded['mcp_credential_id'] ?? null)
        || ! is_string($seeded['mcp_secret'] ?? null)
        || ! is_string($seeded['vitals_secret'] ?? null)) {
        failHarness('The live fixture seed returned an invalid shape.');
    }

    $stamp['commands']['seed_exit_code'] = 0;

    $server = new Process([
        PHP_BINARY,
        '-S',
        "127.0.0.1:{$port}",
        $root.'/tests/Live/contract-major-server.php',
    ], $root, $environment);
    $server->setTimeout(null);
    $server->start(static function (string $type, string $output) use ($serverOutput): void {
        fwrite($serverOutput, $output);
        fflush($serverOutput);
    });

    $deadline = hrtime(true) + 8_000_000_000;
    $ready = false;

    do {
        if (! $server->isRunning()) {
            failHarness('The loopback listener exited before readiness.');
        }

        try {
            $probe = rawRequest($port, 'GET', '/bfc/meta');
            $ready = $probe['status'] === 200;
        } catch (RuntimeException) {
            $ready = false;
        }
    } while (! $ready && hrtime(true) < $deadline);

    if (! $ready) {
        failHarness('The loopback listener did not become ready before its deadline.');
    }

    $stamp['transport']['readiness']['verdict'] = 'pass';
    $pid = $server->getPid();

    if (! is_int($pid)) {
        failHarness('The spawned listener did not expose its PID.');
    }

    $stamp['transport']['listener'] = listenerIdentity($pid, $port, $root);

    $authHeaders = static fn (string $major, string $secret, string $client): array => [
        ['BFC-Contract-Version', $major],
        ['Authorization', 'Bearer '.$secret],
        ['X-BfC-Client-Id', $client],
    ];
    $route = '/_bfc-harness/contract-major';

    $acceptedA = rawRequest($port, 'POST', $route, $authHeaders('2', $seeded['mcp_secret'], 'live-client-a'));
    requireSame(200, $acceptedA['status'], 'accepted current-major status');
    $acceptedABody = json_decode($acceptedA['body'], true);
    requireSame($seeded['mcp_credential_id'], $acceptedABody['credential_id'] ?? null, 'accepted credential identity');
    requireSame('live-client-a', $acceptedABody['client_id'] ?? null, 'accepted advisory client identity');
    $stamp['cases']['accepted_current_major'] = observation($acceptedA, 1, [
        'authenticated_as_seeded_credential' => true,
        'observed_client_id' => 'live-client-a',
    ]);

    $acceptedB = rawRequest($port, 'POST', $route, $authHeaders('2', $seeded['mcp_secret'], 'live-client-b'));
    requireSame(200, $acceptedB['status'], 'changed-client-id accepted status');
    $acceptedBBody = json_decode($acceptedB['body'], true);
    requireSame($seeded['mcp_credential_id'], $acceptedBBody['credential_id'] ?? null, 'changed-client-id credential identity');
    requireSame('live-client-b', $acceptedBBody['client_id'] ?? null, 'changed advisory client identity');
    $stamp['cases']['changed_client_id_does_not_change_authority'] = observation($acceptedB, 1, [
        'same_authenticated_credential' => true,
        'observed_client_id' => 'live-client-b',
    ]);

    $afterAccepted = readState($statePath);
    $stamp['accepted_path_counters'] = $afterAccepted;
    requireSame([
        'authentication_entries' => 2,
        'credential_resolver_invocations' => 2,
        'replay_store_reads' => 2,
        'replay_store_writes' => 2,
        'cache_actions' => 2,
        'queue_actions' => 2,
        'domain_actions' => 2,
    ], $afterAccepted, 'accepted-path positive-control counters');

    $missing = rawRequest($port, 'POST', $route, [
        ['Authorization', 'Bearer '.$seeded['mcp_secret']],
        ['X-BfC-Client-Id', 'refusal-client'],
    ]);
    assertRefusal($missing, 400, 'missing_contract_major');
    $stamp['cases']['missing'] = observation($missing, 0, json_decode($missing['body'], true));

    $nonCanonical = rawRequest($port, 'POST', $route, $authHeaders('02', $seeded['mcp_secret'], 'refusal-client'));
    assertRefusal($nonCanonical, 400, 'malformed_contract_major');
    $stamp['cases']['noncanonical'] = observation($nonCanonical, 1, json_decode($nonCanonical['body'], true));

    $duplicate = rawRequest($port, 'POST', $route, [
        ['BFC-Contract-Version', '2'],
        ['BFC-Contract-Version', '2'],
        ['Authorization', 'Bearer '.$seeded['mcp_secret']],
        ['X-BfC-Client-Id', 'refusal-client'],
    ]);
    assertRefusal($duplicate, 400, 'malformed_contract_major');
    $stamp['cases']['duplicate_transport_fields'] = observation($duplicate, 2, json_decode($duplicate['body'], true));

    $unsupported = rawRequest($port, 'POST', $route, $authHeaders('3', $seeded['mcp_secret'], 'claimed-authority'));
    assertRefusal($unsupported, 426, 'unsupported_contract_major');
    $stamp['cases']['unsupported'] = observation($unsupported, 1, json_decode($unsupported['body'], true));

    $marker = 'live-contract-major-malformed-marker';
    $unreflected = rawRequest($port, 'POST', $route, $authHeaders($marker, $seeded['mcp_secret'], 'refusal-client'));
    assertRefusal($unreflected, 400, 'malformed_contract_major');
    fflush($serverOutput);
    $logged = file_get_contents($serverLog);

    if (str_contains($unreflected['body'], $marker)
        || str_contains(json_encode($unreflected['headers'], JSON_THROW_ON_ERROR), $marker)
        || (is_string($logged) && str_contains($logged, $marker))) {
        failHarness('Malformed contract material was reflected in the response or server output.');
    }

    $stamp['cases']['malformed_material_not_reflected'] = observation(
        $unreflected,
        1,
        ['response_headers_logs_exception_output_absent' => true],
    );

    $afterRefusals = readState($statePath);
    requireSame($afterAccepted, $afterRefusals, 'refusal side-effect counters');
    $stamp['cases']['refusals_before_side_effects'] = [
        'state_before' => $afterAccepted,
        'state_after' => $afterRefusals,
        'all_deltas_zero' => true,
        'verdict' => 'pass',
        'exit_code' => 0,
    ];

    $clientOnly = rawRequest($port, 'POST', $route, [
        ['BFC-Contract-Version', '2'],
        ['Authorization', 'Bearer unknown-live-credential'],
        ['X-BfC-Client-Id', 'claimed-authority'],
    ]);
    requireSame(401, $clientOnly['status'], 'client-id-only authority status');
    requireSame('{"message":"Unauthenticated."}', $clientOnly['body'], 'client-id-only authority body');
    $afterClientOnly = readState($statePath);
    requireSame($afterAccepted['domain_actions'], $afterClientOnly['domain_actions'], 'client-id-only domain actions');
    requireSame($afterAccepted['replay_store_reads'], $afterClientOnly['replay_store_reads'], 'client-id-only replay reads');
    requireSame($afterAccepted['replay_store_writes'], $afterClientOnly['replay_store_writes'], 'client-id-only replay writes');
    $stamp['cases']['client_id_does_not_grant_authority'] = observation($clientOnly, 1, [
        'authenticated' => false,
        'domain_reached' => false,
    ]);

    $vitals = rawRequest($port, 'GET', '/bfc/console/vitals', [
        ['BFC-Contract-Version', '1'],
        ['Authorization', 'Bearer '.$seeded['vitals_secret']],
    ]);
    requireSame(200, $vitals['status'], 'unversioned Console vitals status');
    $vitalsBody = json_decode($vitals['body'], true);
    requireSame(2, $vitalsBody['api_version'] ?? null, 'Console vitals server major');
    requireSame('degraded', $vitalsBody['health'] ?? null, 'Console vitals prior-major health');
    $stamp['cases']['console_vitals_prior_major_unversioned'] = observation($vitals, 1, [
        'api_version' => 2,
        'health' => 'degraded',
    ]);

    $stamp['overall_verdict'] = 'pass';
    $stamp['exit_code'] = 0;
} catch (Throwable $failure) {
    $stamp['failure'] = [
        'class' => $failure::class,
        'message' => $failure->getMessage(),
    ];
} finally {
    if ($server instanceof Process) {
        $server->stop(3, SIGTERM);
        $stamp['commands']['listener_exit_code'] = $server->getExitCode();
    }

    if (is_resource($serverOutput)) {
        fclose($serverOutput);
    }

    $absent = listenerAbsent($port, $root);
    $stamp['transport']['teardown']['listener_absent'] = $absent;
    $stamp['transport']['teardown']['verdict'] = $absent ? 'pass' : 'fail';

    if (! $absent) {
        $stamp['overall_verdict'] = 'fail';
        $stamp['exit_code'] = 1;
        $stamp['failure'] ??= [
            'class' => RuntimeException::class,
            'message' => 'The loopback listener remained after bounded teardown.',
        ];
    }

    file_put_contents(
        $stampPath,
        json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
    );

    foreach (scandir($runDirectory) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..' && is_file($runDirectory.'/'.$entry)) {
            unlink($runDirectory.'/'.$entry);
        }
    }

    rmdir($runDirectory);
}

if ($stamp['exit_code'] !== 0) {
    fwrite(STDERR, 'contract-major live harness failed; stamp: '.$stampPath."\n");
    exit(1);
}

fwrite(STDOUT, 'contract-major live harness passed; stamp: '.$stampPath."\n");
