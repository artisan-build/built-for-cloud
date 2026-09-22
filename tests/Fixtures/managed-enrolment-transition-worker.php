<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\User;
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
    'built-for-cloud' => [
        'managed' => [
            'client_secret' => $input['client_secret'],
            'ca_bundle' => null,
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
Container::setInstance($container);
Facade::setFacadeApplication($container);
$connection = $capsule->getConnection('pgsql_testing');
$connection->statement("set application_name = 'bfc-p1-atomicity-worker-".(int) $input['worker']."'");
$user = User::query()->where('email', $input['owner_email'])->sole();

$refused = false;
$message = null;

try {
    (new ManagedTransitions(new Factory))->prepare($user, ManagedTransitionDirection::Exit, [
        'issuer' => $input['expected_issuer'],
        'connection_id' => $input['expected_connection_id'],
        'installation_id' => $input['expected_installation_id'],
        'generation' => (int) $input['expected_generation'],
    ]);
} catch (ManagedAuthRefused $refusal) {
    $refused = true;
    $message = $refusal->getMessage();
}

fwrite(STDOUT, json_encode([
    'refused' => $refused,
    'message' => $message,
], JSON_THROW_ON_ERROR));
