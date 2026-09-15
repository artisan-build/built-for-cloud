<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

/** @return never */
function failAsymmetricHarness(string $message): void
{
    throw new RuntimeException($message);
}

function asymmetricHarnessSame(mixed $expected, mixed $actual, string $label): void
{
    if ($actual !== $expected) {
        failAsymmetricHarness("{$label} did not match its expected value.");
    }
}

function asymmetricHarnessRun(Process $process, string $label, ?array $input = null): string
{
    if ($input !== null) {
        $process->setInput(json_encode($input, JSON_THROW_ON_ERROR));
    }

    if ($process->run() !== 0) {
        failAsymmetricHarness("{$label} failed: ".$process->getErrorOutput());
    }

    return $process->getOutput();
}

function asymmetricHarnessPort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

    if (! is_resource($socket)) {
        failAsymmetricHarness('The OS could not allocate a loopback port.');
    }

    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = is_string($address) ? parse_url('tcp://'.$address, PHP_URL_PORT) : false;

    return is_int($port) ? $port : failAsymmetricHarness('The allocated loopback port could not be read.');
}

/** @return array{status: int, headers: array<string, list<string>>, body: string} */
function asymmetricHarnessRequest(int $port, string $method, string $path, string $body = ''): array
{
    $socket = @stream_socket_client("tcp://127.0.0.1:{$port}", $errorNumber, $error, 0.4, STREAM_CLIENT_CONNECT);

    if (! is_resource($socket)) {
        failAsymmetricHarness('Could not connect to the bounded loopback enrollment server.');
    }

    stream_set_timeout($socket, 3);
    $request = "{$method} {$path} HTTP/1.1\r\n"
        ."Host: 127.0.0.1:{$port}\r\n"
        ."Accept: application/json\r\n"
        ."Content-Type: application/json\r\n"
        ."Connection: close\r\n"
        .'Content-Length: '.strlen($body)."\r\n\r\n{$body}";
    $offset = 0;

    while ($offset < strlen($request)) {
        $written = fwrite($socket, substr($request, $offset));

        if ($written === false || $written === 0) {
            fclose($socket);
            failAsymmetricHarness('The enrollment request could not be written completely.');
        }

        $offset += $written;
    }

    $raw = '';

    while (! feof($socket)) {
        $chunk = fread($socket, 8192);

        if ($chunk === false) {
            fclose($socket);
            failAsymmetricHarness('The enrollment response could not be read.');
        }

        $raw .= $chunk;
    }

    fclose($socket);
    [$head, $responseBody] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
    $lines = explode("\r\n", $head);
    $statusLine = array_shift($lines);

    if (! is_string($statusLine) || preg_match('/^HTTP\/\S+ ([0-9]{3}) /', $statusLine, $matches) !== 1) {
        failAsymmetricHarness('The enrollment response had no valid status line.');
    }

    $headers = [];

    foreach ($lines as $line) {
        if (! str_contains($line, ':')) {
            continue;
        }

        [$name, $value] = explode(':', $line, 2);
        $headers[strtolower($name)][] = trim($value);
    }

    return ['status' => (int) $matches[1], 'headers' => $headers, 'body' => $responseBody];
}

/** @param array<string, string> $environment */
function startAsymmetricHarnessServer(string $root, int $port, array $environment, string $mode, string $log): Process
{
    $serverEnvironment = array_merge($environment, ['BFC_HARNESS_ASYMMETRIC' => $mode]);
    $server = new Process([
        PHP_BINARY,
        '-S',
        "127.0.0.1:{$port}",
        $root.'/tests/Live/asymmetric-enrollment-server.php',
    ], $root, $serverEnvironment);
    $server->setTimeout(null);
    $server->start(static function (string $type, string $output) use ($log): void {
        file_put_contents($log, $output, FILE_APPEND);
    });
    $deadline = hrtime(true) + 8_000_000_000;

    do {
        if (! $server->isRunning()) {
            failAsymmetricHarness('The enrollment listener exited before readiness.');
        }

        try {
            $ready = asymmetricHarnessRequest($port, 'GET', '/bfc/meta')['status'] === 200;
        } catch (RuntimeException) {
            $ready = false;
        }
    } while (! $ready && hrtime(true) < $deadline);

    if (! $ready) {
        failAsymmetricHarness('The enrollment listener missed its readiness deadline.');
    }

    return $server;
}

function stopAsymmetricHarnessServer(?Process &$server): void
{
    if ($server instanceof Process) {
        $server->stop(3, SIGTERM);
        $server = null;
    }
}

$root = dirname(__DIR__, 2);
$stampPath = $argv[1] ?? '';

if ($stampPath === '') {
    fwrite(STDERR, "usage: php tests/Live/run-asymmetric-enrollment-harness.php <stamp-path>\n");
    exit(2);
}

$stampDirectory = dirname($stampPath);

if (! is_dir($stampDirectory) && ! mkdir($stampDirectory, 0777, true) && ! is_dir($stampDirectory)) {
    fwrite(STDERR, "Could not create the stamp directory.\n");
    exit(2);
}

$runDirectory = sys_get_temp_dir().'/bfc-asymmetric-enrollment-'.bin2hex(random_bytes(8));

if (! mkdir($runDirectory, 0700)) {
    fwrite(STDERR, "Could not create the protected harness directory.\n");
    exit(2);
}

$database = $runDirectory.'/database.sqlite';
$serverLog = $runDirectory.'/server.log';
$port = asymmetricHarnessPort();
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
    'BFC_HARNESS_ASYMMETRIC' => 'bound',
]);
$stamp = [
    'schema' => 'bfc.asymmetric-enrollment.loopback.v1',
    'candidate_sha' => null,
    'runtime' => ['php' => PHP_VERSION, 'laravel' => Application::VERSION],
    'transport' => ['kind' => 'tcp-loopback', 'port' => $port, 'bounded_readiness' => true, 'bounded_teardown' => true],
    'cases' => [],
    'private_key_storage' => 'memory-only',
    'overall_verdict' => 'fail',
    'exit_code' => 1,
];
$server = null;
$privatePem = null;
$publicKey = null;
$code = null;

try {
    touch($database);
    chmod($database, 0600);
    touch($serverLog);
    chmod($serverLog, 0600);
    $stamp['candidate_sha'] = trim(asymmetricHarnessRun(new Process(['git', 'rev-parse', 'HEAD'], $root), 'candidate SHA read'));
    asymmetricHarnessRun(new Process([
        $root.'/vendor/bin/testbench',
        'migrate:fresh',
        '--force',
        '--no-interaction',
    ], $root, $environment), 'harness migration');
    $seed = json_decode(asymmetricHarnessRun(
        new Process([PHP_BINARY, $root.'/tests/Live/seed-asymmetric-enrollment-harness.php'], $root, $environment),
        'harness seed',
    ), true, flags: JSON_THROW_ON_ERROR);

    if (! is_string($seed['credential_id'] ?? null) || ! is_string($seed['enrollment_code'] ?? null)) {
        failAsymmetricHarness('The harness seed returned an invalid shape.');
    }

    $code = $seed['enrollment_code'];
    $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $details = $privateKey instanceof OpenSSLAsymmetricKey ? openssl_pkey_get_details($privateKey) : false;

    if (! $privateKey instanceof OpenSSLAsymmetricKey || ! is_array($details) || ! is_string($details['key'] ?? null)) {
        failAsymmetricHarness('The client could not generate its in-memory RSA keypair.');
    }

    $publicKey = $details['key'];
    openssl_pkey_export($privateKey, $privatePem);

    if (! is_string($privatePem)) {
        failAsymmetricHarness('The in-memory private-marker refusal fixture could not be produced.');
    }

    $path = '/bfc/asymmetric-enrollments/app_live_1';
    $requestBody = static fn (string $key): string => json_encode([
        'enrollment_code' => $code,
        'public_key' => $key,
    ], JSON_THROW_ON_ERROR);

    $server = startAsymmetricHarnessServer($root, $port, $environment, 'default', $serverLog);
    $defaultRefusal = asymmetricHarnessRequest($port, 'POST', $path, $requestBody($publicKey));
    asymmetricHarnessSame(404, $defaultRefusal['status'], 'default resolver refusal status');
    asymmetricHarnessSame(['message' => 'This asymmetric enrollment is unavailable.'], json_decode($defaultRefusal['body'], true), 'default resolver refusal body');
    stopAsymmetricHarnessServer($server);

    $pendingInspector = static function () use ($root, $environment, $seed): array {
        return json_decode(asymmetricHarnessRun(
            new Process([PHP_BINARY, $root.'/tests/Live/inspect-asymmetric-enrollment-harness.php'], $root, $environment),
            'pending-state inspection',
            ['mode' => 'pending', 'credential_id' => $seed['credential_id']],
        ), true, flags: JSON_THROW_ON_ERROR);
    };
    asymmetricHarnessSame(true, $pendingInspector()['pending_without_material'] ?? null, 'default-refusal persistence');
    $stamp['cases']['default_resolver_refusal'] = ['status' => 404, 'no_state_change' => true];

    $server = startAsymmetricHarnessServer($root, $port, $environment, 'bound', $serverLog);
    $privateRefusal = asymmetricHarnessRequest($port, 'POST', $path, $requestBody($privatePem));
    asymmetricHarnessSame(422, $privateRefusal['status'], 'private-marker refusal status');
    asymmetricHarnessSame(true, $pendingInspector()['pending_without_material'] ?? null, 'private-marker non-persistence');
    $stamp['cases']['private_marker_refusal'] = ['status' => 422, 'no_state_change' => true];

    $success = asymmetricHarnessRequest($port, 'POST', $path, $requestBody($publicKey));
    asymmetricHarnessSame(201, $success['status'], 'enrollment success status');
    asymmetricHarnessSame([
        'credential_id' => $seed['credential_id'],
        'algorithm' => 'RS256',
    ], json_decode($success['body'], true), 'enrollment success body');

    if (! str_contains(implode(', ', $success['headers']['cache-control'] ?? []), 'no-store')) {
        failAsymmetricHarness('The enrollment success omitted Cache-Control no-store.');
    }

    $payload = 'reel-live-session-grant-bytes';

    if (! openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
        failAsymmetricHarness('The retained client private key could not sign the live payload.');
    }

    $inspection = json_decode(asymmetricHarnessRun(
        new Process([PHP_BINARY, $root.'/tests/Live/inspect-asymmetric-enrollment-harness.php'], $root, $environment),
        'active-state and lookup inspection',
        [
            'mode' => 'active',
            'credential_id' => $seed['credential_id'],
            'payload' => $payload,
            'signature' => base64_encode($signature),
        ],
    ), true, flags: JSON_THROW_ON_ERROR);

    foreach ($inspection as $label => $passed) {
        asymmetricHarnessSame(true, $passed, (string) $label);
    }

    $stamp['cases']['public_only_enrollment'] = array_merge([
        'status' => 201,
        'response_exact_fields' => true,
        'cache_control_no_store' => true,
        'request_contains_private_key' => false,
        'response_contains_key_or_code' => false,
    ], $inspection);
    stopAsymmetricHarnessServer($server);
    $log = file_get_contents($serverLog);

    if (! is_string($log)
        || str_contains($log, $code)
        || str_contains($log, $publicKey)
        || str_contains($log, $privatePem)
        || str_contains($success['body'], $code)
        || str_contains($success['body'], 'PUBLIC KEY')
        || str_contains($success['body'], 'PRIVATE KEY')) {
        failAsymmetricHarness('Enrollment material appeared in the response or server log.');
    }

    $stamp['cases']['response_log_non_leakage'] = true;
    $stamp['overall_verdict'] = 'pass';
    $stamp['exit_code'] = 0;
} catch (Throwable $failure) {
    $stamp['failure'] = ['class' => $failure::class, 'message' => $failure->getMessage()];
} finally {
    stopAsymmetricHarnessServer($server);
    $privatePem = null;
    $publicKey = null;
    $code = null;

    foreach (scandir($runDirectory) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..' && is_file($runDirectory.'/'.$entry)) {
            unlink($runDirectory.'/'.$entry);
        }
    }

    rmdir($runDirectory);
    file_put_contents($stampPath, json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
}

if ($stamp['exit_code'] !== 0) {
    fwrite(STDERR, 'asymmetric enrollment live harness failed; stamp: '.$stampPath."\n");
    exit(1);
}

fwrite(STDOUT, 'asymmetric enrollment live harness passed; stamp: '.$stampPath."\n");
