<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\HttpContract;
use ArtisanBuild\BuiltForCloud\Testing\BoundedWait;
use ArtisanBuild\BuiltForCloud\Testing\DisposablePostgresLane;
use ArtisanBuild\BuiltForCloud\Testing\P6ArchiveProof;
use ArtisanBuild\BuiltForCloud\Testing\P6GateCommandLedger;
use ArtisanBuild\BuiltForCloud\Testing\P6GateContract;
use ArtisanBuild\BuiltForCloud\Testing\P6GateRecorder;
use ArtisanBuild\BuiltForCloud\Testing\P6GateStamp;
use ArtisanBuild\BuiltForCloud\Testing\P6LoopbackProcess;
use ArtisanBuild\BuiltForCloud\Testing\P6PostgresRunStamp;
use ArtisanBuild\BuiltForCloud\Testing\P6RuntimeCounterProof;
use ArtisanBuild\BuiltForCloud\Testing\P6SecretLeakDetector;
use ArtisanBuild\BuiltForCloud\Testing\PostgresAdministrator;
use ArtisanBuild\BuiltForCloud\Testing\SharedRuntimeIdentity;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6HttpClient;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6LiveCommandRunner;
use ArtisanBuild\BuiltForCloud\Tests\Support\P6LiveSecretMaterial;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Purpose;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

/** @return never */
function p6LiveFail(string $message): void
{
    throw new RuntimeException($message);
}

function p6LiveSame(mixed $expected, mixed $actual, string $label): void
{
    if ($actual !== $expected) {
        p6LiveFail("{$label} did not match its expected value.");
    }
}

/** @return array<string, mixed> */
function p6LiveJson(string $json, string $label): array
{
    $decoded = json_decode($json, true);

    return is_array($decoded) && ! array_is_list($decoded)
        ? $decoded
        : throw new RuntimeException("{$label} did not return a JSON object.");
}

/** @param array<string, string> $environment */
function p6LiveRun(array $command, string $directory, array $environment, string $label, array &$arguments, array &$outputs): string
{
    return P6LiveCommandRunner::run($command, $directory, $environment, $label, $arguments, $outputs);
}

/** @param array<string, string> $environment */
function p6LiveRunSensitive(array $command, string $directory, array $environment, string $input, string $label, array &$arguments): string
{
    $arguments[] = $command;
    $process = new Process($command, $directory, $environment, $input, 60);
    if ($process->run() !== 0) {
        p6LiveFail("{$label} exited non-zero.");
    }

    return $process->getOutput();
}

function p6LiveSigningKey(): AsymmetricSecretKey
{
    foreach (range(1, 16) as $ignored) {
        $key = AsymmetricSecretKey::generate(new Version4);
        if (strlen($key->raw()) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return $key;
        }
    }

    p6LiveFail('The local P6 fixture authority could not create a signing key.');
}

/** @param array<string, mixed> $overrides */
function p6LiveAssertion(AsymmetricSecretKey $key, string $audience, array $overrides = []): string
{
    $now = new DateTimeImmutable;
    $claims = array_merge([
        'iss' => 'https://p6-authority.test',
        'sub' => 'p6-operator',
        'aud' => $audience,
        'iat' => $now->format(DATE_ATOM),
        'nbf' => $now->format(DATE_ATOM),
        'exp' => $now->modify('+90 seconds')->format(DATE_ATOM),
        'jti' => 'p6_'.bin2hex(random_bytes(12)),
        'display_name' => 'P6 Operator',
        'role' => 'admin',
        'purpose' => 'mcp',
    ], $overrides);

    return (new Builder)
        ->setVersion(new Version4)
        ->setPurpose(Purpose::public())
        ->setKey($key)
        ->setClaims($claims)
        ->setFooterArray(['kid' => 'p6-live-key'])
        ->toString();
}

/** @param array{status: int, headers: array<string, list<string>>, body: string} $response */
function p6LiveStatus(array $response, int $status, string $label): true
{
    p6LiveSame($status, $response['status'], $label.' status');

    return true;
}

/** @return array<string, int> */
function p6LiveState(P6HttpClient $client, P6LoopbackProcess $listener): array
{
    $response = $client->request($listener->port, 'GET', '/_bfc-p6c/state');
    p6LiveStatus($response, 200, 'shared runtime state');
    $state = p6LiveJson($response['body'], 'shared runtime state');
    $counters = [];

    foreach ($state as $counter => $value) {
        if (! is_string($counter) || ! is_int($value)) {
            p6LiveFail('The shared runtime state contained a non-integer counter.');
        }

        $counters[$counter] = $value;
    }

    return $counters;
}

/** @param array{status: int, headers: array<string, list<string>>, body: string} $response */
function p6LiveContractRefusal(array $response, int $status, string $error): true
{
    p6LiveStatus($response, $status, $error);
    p6LiveSame(
        ['error' => $error, 'supported_contract_major' => BuiltForCloud::API_VERSION],
        p6LiveJson($response['body'], $error),
        $error.' body',
    );
    $cache = implode(',', $response['headers']['cache-control'] ?? []);
    if (preg_match('/(?:^|,)\s*no-store\s*(?:,|$)/i', $cache) !== 1
        || array_key_exists('retry-after', $response['headers'])) {
        p6LiveFail("{$error} response headers were invalid.");
    }

    return true;
}

/** @return array<string, string> */
function p6LiveEnvironment(PostgresAdministrator $admin, string $database, string $appKey, string $audience, string $authoritySecret): array
{
    $base = getenv();
    $base = is_array($base) ? array_filter($base, 'is_string') : [];

    return array_merge($base, [
        'APP_ENV' => 'testing',
        'APP_DEBUG' => 'false',
        'APP_KEY' => $appKey,
        'APP_URL' => 'http://127.0.0.1',
        'DB_CONNECTION' => 'pgsql',
        'DB_HOST' => $admin->host,
        'DB_PORT' => (string) $admin->port,
        'DB_DATABASE' => $database,
        'DB_USERNAME' => $admin->username,
        'DB_PASSWORD' => $admin->password,
        'DB_SSLMODE' => $admin->sslMode,
        'CACHE_STORE' => 'database',
        'SESSION_DRIVER' => 'cookie',
        'QUEUE_CONNECTION' => 'database',
        'MAIL_MAILER' => 'array',
        'BFC_P6_AUDIENCE' => $audience,
        'BFC_P6_AUTHORITY_SECRET' => $authoritySecret,
    ]);
}

function p6LiveCopy(string $source, string $target): void
{
    if (! copy($source, $target)) {
        p6LiveFail('A P6c fresh-host fixture file could not be installed.');
    }
}

function p6LiveRemoveTree(string $path): void
{
    if (! is_dir($path)) {
        return;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );
    foreach ($iterator as $entry) {
        if (! $entry instanceof SplFileInfo) {
            continue;
        }
        $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($path);
}

/** @return array<string, mixed> */
function p6LiveDatabaseSurface(PDO $database): array
{
    $tables = $database->query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )->fetchAll(PDO::FETCH_COLUMN);
    $surface = [];
    foreach ($tables as $table) {
        if (! is_string($table) || preg_match('/^[a-z0-9_]+$/D', $table) !== 1) {
            continue;
        }
        $surface[$table] = $database->query('SELECT * FROM "'.$table.'"')->fetchAll(PDO::FETCH_ASSOC);
    }

    return $surface;
}

/** @param list<string> $forbidden
 * @return list<string>
 */
function p6LiveFileLeaks(string $root, array $forbidden): array
{
    $leaks = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $entry) {
        if (! $entry instanceof SplFileInfo || ! $entry->isFile() || str_contains($entry->getPathname(), '/vendor/')) {
            continue;
        }
        $contents = file_get_contents($entry->getPathname());
        if (! is_string($contents)) {
            continue;
        }
        foreach ($forbidden as $material) {
            if ($material !== '' && str_contains($contents, $material)) {
                p6LiveFail('The P6c secret detector found forbidden material in a generated file.');
            }
        }
    }

    return $leaks;
}

$root = dirname(__DIR__, 2);
$stampPath = getenv('BFC_P6_LIVE_STAMP');
$commandStamp = getenv('BFC_P6_COMMAND_STAMP');
$postgresStamp = getenv('BFC_P6_PGSQL_STAMP');
if (! is_string($stampPath) || $stampPath === ''
    || ! is_string($commandStamp) || $commandStamp === ''
    || ! is_string($postgresStamp) || $postgresStamp === '') {
    fwrite(STDERR, "BFC_P6_LIVE_STAMP, BFC_P6_COMMAND_STAMP, and BFC_P6_PGSQL_STAMP are required.\n");
    exit(2);
}

$runDirectory = sys_get_temp_dir().'/bfc-p6-live-'.bin2hex(random_bytes(12));
if (! mkdir($runDirectory, 0700)) {
    fwrite(STDERR, "Could not create the private P6c run directory.\n");
    exit(2);
}
$manifestDirectory = $runDirectory.'/manifest';
$sourceDirectory = $runDirectory.'/source';
$artifactDirectory = $runDirectory.'/artifacts';
mkdir($manifestDirectory, 0700);
mkdir($sourceDirectory, 0700);
mkdir($artifactDirectory, 0700);

$listenerA = null;
$listenerB = null;
$worker = null;
$lane = null;
$failure = null;
$arguments = [];
$outputs = [];
$responses = [];
$listenerIdentities = [];
$archivePath = '';
$archiveChecksum = '';
$installedVersion = '';
$runtime = ['php' => PHP_VERSION, 'laravel' => '', 'postgres' => ''];
$shared = [];
$postgresCases = array_fill_keys(P6GateContract::POSTGRES_CASES, 'not-run');
$teardown = [
    'bounded' => true,
    'listeners_absent' => false,
    'database_absent' => false,
    'manifest_absent' => false,
    'verdict' => 'fail',
];
$cases = new P6GateRecorder(P6GateContract::LIVE_CASES);
$commandResults = [];
$candidateSha = '';
$databaseName = '';
$matrixDatabaseName = '';
$liveMarkerVerified = false;
$forbidden = [];

try {
    if (trim((string) p6LiveRun(['git', 'status', '--porcelain'], $root, [], 'clean-tree check', $arguments, $outputs)) !== '') {
        p6LiveFail('The P6c live runner requires a clean committed tree.');
    }
    $candidateSha = trim(p6LiveRun(['git', 'rev-parse', 'HEAD'], $root, [], 'candidate SHA', $arguments, $outputs));
    $commandResults = P6GateCommandLedger::completedForLiveRunner($commandStamp, $candidateSha);
    $postgresEvidence = P6PostgresRunStamp::read($postgresStamp);
    $postgresCases = $postgresEvidence['cases'];
    $matrixDatabaseName = $postgresEvidence['database_name'];

    $administrator = PostgresAdministrator::fromEnvironment();
    $lane = DisposablePostgresLane::create($administrator, $manifestDirectory);
    $databaseName = $lane->databaseName();
    $lane->assertOwned();
    $targetPdo = $administrator->connect($databaseName);
    $runtime['postgres'] = (string) $targetPdo->query('show server_version')->fetchColumn();

    $tar = $runDirectory.'/candidate.tar';
    p6LiveRun(['git', 'archive', '--format=tar', '--output='.$tar, $candidateSha], $root, [], 'candidate archive export', $arguments, $outputs);
    p6LiveRun(['tar', '-xf', $tar, '-C', $sourceDirectory], $root, [], 'candidate archive extraction', $arguments, $outputs);
    unlink($tar);
    $archiveEnvironment = ['COMPOSER_ROOT_VERSION' => '0.0.0+p6c.'.$candidateSha];
    p6LiveRun(
        ['composer', 'archive', '--format=zip', '--dir='.$artifactDirectory, '--file=built-for-cloud'],
        $sourceDirectory,
        $archiveEnvironment,
        'Composer candidate archive',
        $arguments,
        $outputs,
    );
    $archives = glob($artifactDirectory.'/*.zip') ?: [];
    if (count($archives) !== 1) {
        p6LiveFail('Composer did not produce exactly one candidate package archive.');
    }
    $archivePath = $archives[0];
    $archiveChecksum = hash_file('sha256', $archivePath);
    if (! is_string($archiveChecksum)) {
        p6LiveFail('The candidate package archive checksum could not be read.');
    }

    $host = $runDirectory.'/host';
    p6LiveRun(
        P6LiveCommandRunner::freshLaravelHostCommand($host),
        $runDirectory,
        [],
        'fresh Laravel host creation',
        $arguments,
        $outputs,
    );
    $composerPath = $host.'/composer.json';
    $composer = p6LiveJson((string) file_get_contents($composerPath), 'fresh host composer.json');
    $package = p6LiveJson((string) file_get_contents($sourceDirectory.'/composer.json'), 'candidate composer.json');
    $package['version'] = '0.0.0+p6c.'.$candidateSha;
    $package['dist'] = ['type' => 'zip', 'url' => $archivePath];
    $composer['repositories'] = [['type' => 'package', 'canonical' => true, 'package' => $package]];
    $composer['require']['artisan-build/built-for-cloud'] = '0.0.0+p6c.'.$candidateSha;
    file_put_contents($composerPath, json_encode($composer, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
    @unlink($host.'/composer.lock');
    p6LiveRun(P6LiveCommandRunner::archiveInstallCommand(), $host, [], 'fresh host archive install', $arguments, $outputs);
    $lock = p6LiveJson((string) file_get_contents($host.'/composer.lock'), 'fresh host composer.lock');
    $installedVersion = P6ArchiveProof::assertInstalled($lock, $candidateSha, $archivePath);

    foreach (glob($host.'/database/migrations/*.php') ?: [] as $migration) {
        unlink($migration);
    }
    p6LiveCopy(__DIR__.'/p6c-host-migration.php', $host.'/database/migrations/0001_01_01_000004_create_p6_live_tables.php');
    if (! is_dir($host.'/app/Support') && ! mkdir($host.'/app/Support', 0755)) {
        p6LiveFail('The fresh host support directory could not be created.');
    }
    p6LiveCopy(__DIR__.'/P6LiveState.php', $host.'/app/Support/P6LiveState.php');
    p6LiveCopy(__DIR__.'/P6LiveManagedUser.php', $host.'/app/Support/P6LiveManagedUser.php');
    p6LiveCopy(__DIR__.'/P6LiveServiceProvider.php', $host.'/app/Providers/P6LiveServiceProvider.php');
    p6LiveCopy(__DIR__.'/p6c-host-cli.php', $host.'/p6c-host-cli.php');
    file_put_contents(
        $host.'/bootstrap/providers.php',
        "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n    App\\Providers\\P6LiveServiceProvider::class,\n];\n",
    );
    p6LiveRun(['composer', 'dump-autoload', '--no-interaction'], $host, [], 'fresh host autoload', $arguments, $outputs);

    $appKey = 'base64:'.base64_encode(random_bytes(32));
    $authoritySecret = 'p6-authority-'.bin2hex(random_bytes(24));
    $audience = 'urn:bfc:installation:'.$databaseName;
    $environment = p6LiveEnvironment($administrator, $databaseName, $appKey, $audience, $authoritySecret);
    $forbidden = array_values(array_filter([
        $appKey,
        $authoritySecret,
        $administrator->password,
        'p6-canary-'.bin2hex(random_bytes(16)),
    ], static fn (string $material): bool => $material !== ''));

    $cases->observe('fresh_migration_and_install', function () use ($host, $environment, $installedVersion, &$arguments, &$outputs): bool {
        p6LiveRun([PHP_BINARY, 'artisan', 'migrate:fresh', '--force', '--no-interaction'], $host, $environment, 'fresh host migration', $arguments, $outputs);
        $result = p6LiveJson(p6LiveRunSensitive(
            [PHP_BINARY, 'p6c-host-cli.php', 'install'],
            $host,
            $environment,
            json_encode(['version' => $installedVersion], JSON_THROW_ON_ERROR),
            'fresh host install',
            $arguments,
        ), 'fresh host install');
        p6LiveSame('replaced', $result['environment'] ?? null, 'first install environment');
        p6LiveSame('unchanged', $result['composer'] ?? null, 'first install composer');

        return true;
    });
    $lane->assertOwned();
    $cases->observe('identical_install_rerun', function () use ($host, $environment, $installedVersion, &$arguments): bool {
        $result = p6LiveJson(p6LiveRunSensitive(
            [PHP_BINARY, 'p6c-host-cli.php', 'install'],
            $host,
            $environment,
            json_encode(['version' => $installedVersion], JSON_THROW_ON_ERROR),
            'fresh host install rerun',
            $arguments,
        ), 'fresh host install rerun');
        p6LiveSame(['environment' => 'unchanged', 'composer' => 'unchanged'], $result, 'identical install rerun');

        return true;
    });

    $signingKey = p6LiveSigningKey();
    $password = 'p6-password-'.bin2hex(random_bytes(20));
    $seed = p6LiveJson(p6LiveRunSensitive(
        [PHP_BINARY, 'p6c-host-cli.php', 'seed'],
        $host,
        $environment,
        json_encode(['public_key' => $signingKey->getPublicKey()->toHexString(), 'password' => $password], JSON_THROW_ON_ERROR),
        'fresh host fixture seed',
        $arguments,
    ), 'fresh host fixture seed');
    foreach (['mcp_id', 'mcp_secret', 'wrong_secret', 'operator_secret', 'user_id', 'email'] as $key) {
        if (! is_string($seed[$key] ?? null) || $seed[$key] === '') {
            p6LiveFail('The fresh host fixture seed returned an invalid shape.');
        }
    }
    array_push($forbidden, $password, P6LiveSecretMaterial::signingKey($signingKey), $seed['mcp_secret'], $seed['wrong_secret'], $seed['operator_secret']);

    $ready = static function (int $port): bool {
        try {
            return (new P6HttpClient)->request($port, 'GET', '/_bfc-p6c/runtime')['status'] === 200;
        } catch (Throwable) {
            return false;
        }
    };
    $environmentA = array_merge($environment, ['BFC_P6_NODE' => 'a', 'APP_URL' => 'http://127.0.0.1']);
    $environmentB = array_merge($environment, ['BFC_P6_NODE' => 'b', 'APP_URL' => 'http://127.0.0.1']);
    $listenerA = P6LoopbackProcess::start([PHP_BINARY, '-S', '127.0.0.1:{port}', '-t', 'public', 'public/index.php'], $host, $environmentA, $ready);
    $listenerB = P6LoopbackProcess::start([PHP_BINARY, '-S', '127.0.0.1:{port}', '-t', 'public', 'public/index.php'], $host, $environmentB, $ready);
    $listenerIdentities = ['node_a' => $listenerA->identity(), 'node_b' => $listenerB->identity()];
    $arguments[] = $listenerA->command();
    $arguments[] = $listenerB->command();

    $client = new P6HttpClient;
    $runtimeAResponse = $client->request($listenerA->port, 'GET', '/_bfc-p6c/runtime');
    $runtimeBResponse = $client->request($listenerB->port, 'GET', '/_bfc-p6c/runtime');
    p6LiveStatus($runtimeAResponse, 200, 'node A runtime');
    p6LiveStatus($runtimeBResponse, 200, 'node B runtime');
    $runtimeA = p6LiveJson($runtimeAResponse['body'], 'node A runtime');
    $runtimeB = p6LiveJson($runtimeBResponse['body'], 'node B runtime');
    $identityA = new SharedRuntimeIdentity((string) ($runtimeA['database'] ?? ''), is_array($runtimeA['roles'] ?? null) ? $runtimeA['roles'] : []);
    $identityB = new SharedRuntimeIdentity((string) ($runtimeB['database'] ?? ''), is_array($runtimeB['roles'] ?? null) ? $runtimeB['roles'] : []);
    $identityA->assertSameAs($identityB);
    p6LiveSame($databaseName, $identityA->database, 'shared live database identity');
    $shared = ['node_a' => $identityA->jsonSerialize(), 'node_b' => $identityB->jsonSerialize()];
    $runtime['laravel'] = is_string($runtimeA['laravel'] ?? null) ? $runtimeA['laravel'] : '';
    if ($runtime['laravel'] === '' || ($runtimeB['laravel'] ?? null) !== $runtime['laravel']) {
        p6LiveFail('The two P6c nodes did not report one Laravel runtime version.');
    }
    $responses[] = $runtimeAResponse;
    $responses[] = $runtimeBResponse;

    $cases->observe('meta', function () use ($client, $listenerA, &$responses): bool {
        $response = $client->request($listenerA->port, 'GET', '/bfc/meta');
        $responses[] = $response;
        p6LiveStatus($response, 200, 'meta');
        p6LiveSame(BuiltForCloud::API_VERSION, p6LiveJson($response['body'], 'meta')['api_version'] ?? null, 'meta API version');

        return true;
    });
    $contract = static fn (string $value): array => [[HttpContract::MAJOR_HEADER, $value]];
    $mcpHeaders = static fn (string $secret, array $extra = []): array => [
        [HttpContract::MAJOR_HEADER, (string) BuiltForCloud::API_VERSION],
        ['Authorization', 'Bearer '.$secret],
        ...$extra,
    ];
    $cases->observe('contract_major_accepted', function () use ($client, $listenerA, $seed, $mcpHeaders, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($seed['mcp_secret']));
        $responses[] = $response;

        return p6LiveStatus($response, 200, 'accepted contract major');
    });
    $cases->observe('contract_major_missing_refused', function () use ($client, $listenerA, $seed, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', [['Authorization', 'Bearer '.$seed['mcp_secret']]]);
        $responses[] = $response;

        return p6LiveContractRefusal($response, 400, 'missing_contract_major');
    });
    $cases->observe('contract_major_malformed_refused', function () use ($client, $listenerA, $seed, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', [
            [HttpContract::MAJOR_HEADER, '02'], ['Authorization', 'Bearer '.$seed['mcp_secret']],
        ]);
        $responses[] = $response;

        return p6LiveContractRefusal($response, 400, 'malformed_contract_major');
    });
    $cases->observe('contract_major_duplicate_field_refused', function () use ($client, $listenerA, $seed, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', [
            [HttpContract::MAJOR_HEADER, (string) BuiltForCloud::API_VERSION],
            [HttpContract::MAJOR_HEADER, (string) BuiltForCloud::API_VERSION],
            ['Authorization', 'Bearer '.$seed['mcp_secret']],
        ]);
        $responses[] = $response;

        return p6LiveContractRefusal($response, 400, 'malformed_contract_major');
    });
    $cases->observe('contract_major_unsupported_refused', function () use ($client, $listenerA, $seed, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', [
            [HttpContract::MAJOR_HEADER, (string) (BuiltForCloud::API_VERSION + 1)],
            ['Authorization', 'Bearer '.$seed['mcp_secret']],
        ]);
        $responses[] = $response;

        return p6LiveContractRefusal($response, 426, 'unsupported_contract_major');
    });
    $cases->observe('fixed_purpose_admitted', function () use ($client, $listenerB, $seed, $mcpHeaders, &$responses): bool {
        $response = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($seed['mcp_secret']));
        $responses[] = $response;

        return p6LiveStatus($response, 200, 'fixed-purpose admission');
    });
    $cases->observe('wrong_purpose_refused', function () use ($client, $listenerA, $seed, $mcpHeaders, &$responses): bool {
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($seed['wrong_secret']));
        $responses[] = $response;

        return p6LiveStatus($response, 401, 'wrong-purpose refusal');
    });
    $cases->observe('wrong_audience_refused', function () use ($client, $listenerA, $signingKey, $mcpHeaders, &$responses): bool {
        $assertion = p6LiveAssertion($signingKey, 'https://wrong-audience.example.test');
        $response = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($assertion));
        $responses[] = $response;

        return p6LiveStatus($response, 401, 'wrong-audience refusal');
    });
    $cases->observe('wrong_installation_refused', function () use ($client, $listenerB, $signingKey, $mcpHeaders, &$responses): bool {
        $assertion = p6LiveAssertion($signingKey, 'urn:bfc:installation:bfc_p6_'.str_repeat('f', 32));
        $response = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($assertion));
        $responses[] = $response;

        return p6LiveStatus($response, 401, 'wrong-installation refusal');
    });
    $cases->observe('spoofed_client_refused', function () use ($client, $listenerB, $mcpHeaders, &$responses): bool {
        $response = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders(
            'unknown-p6-credential',
            [['X-BfC-Client-Id', 'claimed-operator']],
        ));
        $responses[] = $response;

        return p6LiveStatus($response, 401, 'spoofed-client refusal');
    });
    $replayCountersBefore = p6LiveState($client, $listenerA);
    $cases->observe('cross_node_replay_refused', function () use ($client, $listenerA, $listenerB, $signingKey, $audience, $mcpHeaders, $replayCountersBefore, &$responses): bool {
        $assertion = p6LiveAssertion($signingKey, $audience);
        $accepted = $client->request($listenerA->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($assertion));
        $replayed = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($assertion));
        $responses[] = $accepted;
        $responses[] = $replayed;
        p6LiveStatus($accepted, 200, 'first cross-node assertion');
        p6LiveStatus($replayed, 401, 'cross-node replay');
        P6RuntimeCounterProof::assertDeltas(
            $replayCountersBefore,
            p6LiveState($client, $listenerB),
            ['mcp_on_a' => 1, 'mcp_on_b' => 1],
        );

        return true;
    });

    $rotationCountersBefore = p6LiveState($client, $listenerA);
    $rotation = $client->request($listenerA->port, 'POST', '/bfc/credentials/'.$seed['mcp_id'].'/rotate', [
        ['Authorization', 'Bearer '.$seed['operator_secret']],
        ['Content-Type', 'application/json'],
    ], '{"emergency":true}');
    $responses[] = $rotation;
    p6LiveStatus($rotation, 201, 'credential rotation');
    $rotationBody = p6LiveJson($rotation['body'], 'credential rotation');
    $replacementId = $rotationBody['credential']['id'] ?? null;
    $replacementSecret = $rotationBody['delivery']['secret'] ?? null;
    if (! is_string($replacementId) || ! is_string($replacementSecret) || $replacementSecret === '') {
        p6LiveFail('Credential rotation did not return a replacement through the package transport.');
    }
    $forbidden[] = $replacementSecret;
    $cases->observe('cross_node_rotation_visible', function () use ($client, $listenerB, $seed, $replacementSecret, $mcpHeaders, $rotationCountersBefore, &$responses): bool {
        $replacement = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($replacementSecret));
        $old = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($seed['mcp_secret']));
        $responses[] = $replacement;
        $responses[] = $old;
        p6LiveStatus($replacement, 200, 'cross-node replacement visibility');
        p6LiveStatus($old, 401, 'cross-node emergency rotation retirement');
        P6RuntimeCounterProof::assertDeltas(
            $rotationCountersBefore,
            p6LiveState($client, $listenerB),
            ['credential_rotate_on_a' => 1, 'mcp_on_b' => 2],
        );

        return true;
    });
    $revocationCountersBefore = p6LiveState($client, $listenerA);
    $revocation = $client->request($listenerA->port, 'DELETE', '/bfc/credentials/'.$replacementId, [
        ['Authorization', 'Bearer '.$seed['operator_secret']],
    ]);
    $responses[] = $revocation;
    p6LiveStatus($revocation, 204, 'credential revocation');
    $cases->observe('cross_node_revocation_visible', function () use ($client, $listenerB, $replacementSecret, $mcpHeaders, $revocationCountersBefore, &$responses): bool {
        $response = $client->request($listenerB->port, 'POST', '/_bfc-p6c/mcp', $mcpHeaders($replacementSecret));
        $responses[] = $response;
        p6LiveStatus($response, 401, 'cross-node revocation visibility');
        P6RuntimeCounterProof::assertDeltas(
            $revocationCountersBefore,
            p6LiveState($client, $listenerB),
            ['credential_revoke_on_a' => 1, 'mcp_on_b' => 1],
        );

        return true;
    });

    $sessionCountersBefore = p6LiveState($client, $listenerA);
    $session = new P6HttpClient;
    $login = $session->request($listenerA->port, 'GET', '/bfc/login', [['Accept', 'text/html']]);
    $responses[] = $login;
    if (preg_match('/name="_token" value="([^"]+)"/', $login['body'], $csrf) !== 1) {
        p6LiveFail('The package login form did not expose a CSRF field.');
    }
    $form = http_build_query(['_token' => html_entity_decode($csrf[1]), 'email' => $seed['email'], 'password' => $password]);
    $loggedIn = $session->request($listenerA->port, 'POST', '/bfc/login', [
        ['Content-Type', 'application/x-www-form-urlencoded'], ['Accept', 'text/html'],
    ], $form);
    $responses[] = $loggedIn;
    $cases->observe('session_established_on_a', static fn (): true => p6LiveStatus($loggedIn, 302, 'session establishment on node A'));
    $acceptedA = $session->request($listenerA->port, 'GET', '/_bfc-p6c/session');
    $responses[] = $acceptedA;
    p6LiveStatus($acceptedA, 200, 'session check on node A');
    p6LiveSame($seed['user_id'], p6LiveJson($acceptedA['body'], 'node A session')['user_id'] ?? null, 'node A session user');
    $staleSession = clone $session;
    $cases->observe('session_accepted_on_b', function () use ($staleSession, $listenerB, $seed, &$responses): bool {
        $response = $staleSession->request($listenerB->port, 'GET', '/_bfc-p6c/session');
        $responses[] = $response;
        p6LiveStatus($response, 200, 'session acceptance on node B');
        $body = p6LiveJson($response['body'], 'session acceptance on node B');
        p6LiveSame('b', $body['node'] ?? null, 'session acceptance node');
        p6LiveSame($seed['user_id'], $body['user_id'] ?? null, 'node B session user');

        return true;
    });
    $cases->observe('session_invalidated_on_a', function () use ($session, $listenerA, &$responses): bool {
        $response = $session->request($listenerA->port, 'POST', '/_bfc-p6c/session/invalidate');
        $responses[] = $response;
        p6LiveStatus($response, 200, 'session invalidation on node A');
        p6LiveSame(true, p6LiveJson($response['body'], 'session invalidation on node A')['invalidated'] ?? null, 'session invalidation result');

        return true;
    });
    $cases->observe('session_refused_on_b', function () use ($staleSession, $listenerB, &$responses): bool {
        $response = $staleSession->request($listenerB->port, 'GET', '/_bfc-p6c/session');
        $responses[] = $response;
        p6LiveStatus($response, 401, 'invalidated session refusal on node B');

        return true;
    });
    P6RuntimeCounterProof::assertDeltas(
        $sessionCountersBefore,
        p6LiveState($client, $listenerB),
        [
            'session_establish_on_a' => 1,
            'session_accept_on_a' => 1,
            'session_accept_on_b' => 2,
            'session_invalidate_on_a' => 1,
        ],
    );

    $managedCountersBefore = p6LiveState($client, $listenerA);
    $managed = p6LiveJson(p6LiveRunSensitive(
        [PHP_BINARY, 'p6c-host-cli.php', 'managed'],
        $host,
        $environment,
        '{}',
        'managed fixture setup',
        $arguments,
    ), 'managed fixture setup');
    $managedUser = $managed['user_id'] ?? null;
    if (! is_string($managedUser)) {
        p6LiveFail('The managed fixture setup returned no user identity.');
    }
    $worker = new Process([PHP_BINARY, $root.'/tests/Live/p6c-request-worker.php'], $root, [], json_encode([
        'port' => $listenerA->port,
        'method' => 'POST',
        'path' => '/_bfc-p6c/managed-refresh/'.$managedUser,
    ], JSON_THROW_ON_ERROR), 20);
    $arguments[] = [PHP_BINARY, $root.'/tests/Live/p6c-request-worker.php'];
    $worker->start();
    BoundedWait::until(function () use ($client, $listenerB): bool {
        $state = p6LiveJson($client->request($listenerB->port, 'GET', '/_bfc-p6c/state')['body'], 'refresh barrier state');

        return ($state['refresh_entered'] ?? null) === 1;
    }, 10, 'The shared managed refresh did not reach its deterministic barrier.');
    $secondRefresh = $client->request($listenerB->port, 'POST', '/_bfc-p6c/managed-refresh/'.$managedUser);
    $responses[] = $secondRefresh;
    p6LiveStatus($secondRefresh, 200, 'second managed freshness request');
    p6LiveSame(true, p6LiveJson($secondRefresh['body'], 'second managed freshness request')['allowed'] ?? null, 'second managed freshness result');
    $release = $client->request($listenerB->port, 'POST', '/_bfc-p6c/barrier/release');
    $responses[] = $release;
    p6LiveStatus($release, 200, 'managed refresh barrier release');
    if ($worker->wait() !== 0) {
        p6LiveFail('The first managed freshness request failed.');
    }
    $firstRefresh = p6LiveJson($worker->getOutput(), 'first managed freshness request');
    p6LiveSame(200, $firstRefresh['status'] ?? null, 'first managed freshness status');
    $responses[] = $firstRefresh;
    p6LiveSame(
        true,
        p6LiveJson(is_string($firstRefresh['body'] ?? null) ? $firstRefresh['body'] : '', 'first managed freshness body')['allowed'] ?? null,
        'first managed freshness result',
    );
    $stateResponse = $client->request($listenerA->port, 'GET', '/_bfc-p6c/state');
    $responses[] = $stateResponse;
    $state = p6LiveJson($stateResponse['body'], 'final runtime counters');
    $cases->observe('single_shared_managed_refresh', static function () use ($state, $managedCountersBefore): bool {
        P6RuntimeCounterProof::assertDeltas(
            $managedCountersBefore,
            $state,
            [
                'authority_refreshes' => 1,
                'managed_refresh_on_a' => 1,
                'managed_refresh_on_b' => 1,
            ],
        );

        return true;
    });
    $cases->observe('both_nodes_handled_traffic', static function () use ($state): bool {
        if (($state['node_a_requests'] ?? 0) < 1 || ($state['node_b_requests'] ?? 0) < 1) {
            p6LiveFail('Both P6c nodes did not handle traffic.');
        }

        return true;
    });

    $databaseSurface = p6LiveDatabaseSurface($targetPdo);
    $responseBodies = array_column($responses, 'body');
    $responseHeaders = array_column($responses, 'headers');
    P6SecretLeakDetector::assertAbsent([
        'process_arguments' => $arguments,
        'files' => p6LiveFileLeaks($runDirectory, $forbidden),
        'logs' => [$listenerA->output(), $listenerB->output()],
        'exception_text' => [],
        'response_bodies' => $responseBodies,
        'response_headers' => $responseHeaders,
        'queue_payloads' => $databaseSurface['jobs'] ?? [],
        'database_plaintext' => $databaseSurface,
        'cache_state' => $databaseSurface['cache'] ?? [],
        'session_state' => [$session->cookies(), $staleSession->cookies()],
        'subsequent_output' => $outputs,
    ], $forbidden);
} catch (Throwable $exception) {
    $failure = $exception;
} finally {
    try {
        if ($worker instanceof Process && $worker->isRunning()) {
            $worker->stop(1, SIGTERM);
        }
    } catch (Throwable $exception) {
        $failure ??= $exception;
    }

    try {
        $workerAbsent = ! $worker instanceof Process || ! $worker->isRunning();
        $listenerAAbsent = ! $listenerA instanceof P6LoopbackProcess || $listenerA->stop();
        $listenerBAbsent = ! $listenerB instanceof P6LoopbackProcess || $listenerB->stop();
        $teardown['listeners_absent'] = $workerAbsent && $listenerAAbsent && $listenerBAbsent;
    } catch (Throwable $exception) {
        $failure ??= $exception;
    }

    try {
        if ($lane instanceof DisposablePostgresLane) {
            $result = $lane->teardown();
            $teardown['database_absent'] = $result->databaseAbsent;
            $teardown['manifest_absent'] = $result->manifestAbsent;
            $liveMarkerVerified = $result->markerVerified;
        }
    } catch (Throwable $exception) {
        $failure ??= $exception;
    }

    try {
        p6LiveRemoveTree($runDirectory);
    } catch (Throwable $exception) {
        $failure ??= $exception;
    }

    if ($teardown['listeners_absent'] && $teardown['database_absent'] && $teardown['manifest_absent'] && ! is_dir($runDirectory)) {
        $teardown['verdict'] = 'pass';
    }
}

if ($failure === null && $teardown['verdict'] === 'pass') {
    try {
        $cases->observe('clean_teardown', static fn (): bool => $teardown === [
            'bounded' => true,
            'listeners_absent' => true,
            'database_absent' => true,
            'manifest_absent' => true,
            'verdict' => 'pass',
        ]);
        $commandResults['composer test:p6c-live'] = ['exit_code' => 0, 'verdict' => 'pass'];
        $stamp = [
            'schema' => P6GateContract::SCHEMA,
            'candidate_sha' => $candidateSha,
            'archive' => [
                'source' => 'composer-package-dist-archive',
                'candidate_sha' => $candidateSha,
                'sha256' => $archiveChecksum,
                'installed_version' => $installedVersion,
            ],
            'runtime' => $runtime,
            'postgres' => [
                'database_name' => $databaseName,
                'matrix_database_name' => $matrixDatabaseName,
                'relationship' => 'separate-run-owned-databases',
                'run_marker_verified' => $liveMarkerVerified,
                'cases' => $postgresCases,
            ],
            'shared_runtime' => $shared,
            'listeners' => $listenerIdentities,
            'commands' => $commandResults,
            'cases' => $cases->completed(),
            'teardown' => $teardown,
            'overall_verdict' => 'pass',
            'exit_code' => 0,
        ];
        P6GateStamp::assertValid($stamp, $forbidden);
    } catch (Throwable $exception) {
        $failure = $exception;
    }
}

if ($failure !== null) {
    $stamp = [
        'schema' => P6GateContract::SCHEMA,
        'candidate_sha' => $candidateSha !== '' ? $candidateSha : null,
        'overall_verdict' => 'fail',
        'exit_code' => 1,
        'failure' => ['class' => $failure::class, 'message' => 'The P6c live runner failed; inspect the local command output.'],
        'teardown' => $teardown,
    ];
}

$stampDirectory = dirname($stampPath);
if (! is_dir($stampDirectory) || file_put_contents(
    $stampPath,
    json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
) === false) {
    fwrite(STDERR, "The P6c stamp could not be written.\n");
    exit(1);
}

if ($failure !== null) {
    fwrite(STDERR, "P6c live runner failed; stamp: {$stampPath}\n");
    exit(1);
}

fwrite(STDOUT, "P6c live runner passed; stamp: {$stampPath}\n");
