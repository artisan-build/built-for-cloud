<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Cache\CacheManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Facade;

require dirname(__DIR__, 2).'/vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
$environment = static fn (string $name, string $default): string => (($value = getenv($name)) === false ? $default : $value);
$database = [
    'driver' => 'pgsql',
    'host' => $environment('PGSQL_TESTING_HOST', '127.0.0.1'),
    'port' => $environment('PGSQL_TESTING_PORT', '5432'),
    'database' => $environment('PGSQL_TESTING_DATABASE', ''),
    'username' => $environment('PGSQL_TESTING_USERNAME', 'postgres'),
    'password' => $environment('PGSQL_TESTING_PASSWORD', 'postgres'),
    'charset' => 'utf8',
    'prefix' => '',
    'prefix_indexes' => true,
    'search_path' => 'public',
    'sslmode' => 'prefer',
];
$container = new Container;
$container->instance('config', new Repository([
    'database' => [
        'default' => 'pgsql_testing',
        'connections' => ['pgsql_testing' => $database],
    ],
    'cache' => [
        'default' => 'database',
        'prefix' => 'bfc-p3c1-shared',
        'stores' => [
            'database' => [
                'driver' => 'database',
                'connection' => 'pgsql_testing',
                'table' => 'cache',
                'lock_connection' => 'pgsql_testing',
                'lock_table' => 'cache_locks',
                'lock_lottery' => [0, 100],
                'encrypt' => false,
            ],
        ],
    ],
    'built-for-cloud' => [
        'managed' => [
            'client_secret' => $input['client_secret'] ?? null,
            'ca_bundle' => $input['ca_bundle'] ?? null,
        ],
    ],
]));
$capsule = new Capsule($container);
$capsule->addConnection($database, 'pgsql_testing');
$container->instance('db', $capsule->getDatabaseManager());
$container->bind('db.schema', static fn (Container $app): mixed => $app['db']->connection()->getSchemaBuilder());
$capsule->getDatabaseManager()->setDefaultConnection('pgsql_testing');
$capsule->setAsGlobal();
$capsule->bootEloquent();
$cache = new CacheManager($container);
$container->instance('cache', $cache);
$container->instance('cache.store', $cache->store());
Container::setInstance($container);
Facade::setFacadeApplication($container);
$connection = $capsule->getConnection('pgsql_testing');
$connection->statement("set application_name = '".str_replace("'", "''", $input['application_name'])."'");
CarbonImmutable::setTestNow($input['now']);
$user = User::query()->where('scalpels_id', $input['subject'])->sole();
$client = new ManagedAuthClient(new Factory);
$responses = new ManagedMembershipResponses(new ManagedIdentityUpsert, $client);

if (($input['mode'] ?? 'decision') === 'apply') {
    $result = $responses->applyConfirmation(
        new ManagedAuthConnection(
            'https://live-issuer.example.test',
            'live-connection',
            'live-organization',
            'live-installation',
            7,
            'https://127.0.0.1:1',
            'unused',
            null,
        ),
        $user,
        new ManagedAuthConfirmation(
            $input['subject'],
            $input['membership_status'],
            $input['connection_status'],
            $input['role'] ?? 'member',
            $input['sequence'],
            $input['sequence'],
            new DateTimeImmutable($input['responded_at'] ?? $input['now']),
        ),
    );
} else {
    $result = (new ManagedFreshness(
        $client,
        $responses,
    ))->allows($user);
}

fwrite(STDOUT, json_encode(['allowed' => $result], JSON_THROW_ON_ERROR));
