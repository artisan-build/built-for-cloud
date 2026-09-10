<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedHandoffClaim;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
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
    'built-for-cloud' => [
        'managed' => [
            'client_secret' => $input['client_secret'],
            'ca_bundle' => $input['ca_bundle'],
        ],
    ],
    'database' => [
        'default' => 'pgsql_testing',
        'connections' => ['pgsql_testing' => $database],
    ],
]));
$capsule = new Capsule($container);
$capsule->addConnection($database, 'pgsql_testing');
$container->instance('db', $capsule->getDatabaseManager());
$capsule->getDatabaseManager()->setDefaultConnection('pgsql_testing');
$capsule->setAsGlobal();
Container::setInstance($container);
Facade::setFacadeApplication($container);
$connection = $capsule->getConnection('pgsql_testing');
$connection->statement("set application_name = 'bfc-p3a-callback-worker-".(int) $input['worker']."'");
$request = Request::create('/bfc/managed/callback', 'GET', [
    'state' => $input['state'],
    'code' => $input['code'],
]);
$session = new Store(
    'bfc-p3a-callback-worker-'.(int) $input['worker'],
    new ArraySessionHandler(300),
);
$session->start();
$session->put(ManagedHandoff::SESSION_NONCE_KEY, $input['session_nonce']);
$request->setLaravelSession($session);
$exchangeReached = false;

try {
    (new ManagedHandoff(
        new ManagedAuthClient(new Factory),
        new ManagedHandoffClaim,
    ))->exchange($request);
    $exchangeReached = true;
} catch (ManagedAuthRefused) {
    // Losing callbacks must stop at the package claim and never reach exchange.
}

fwrite(STDOUT, json_encode([
    'exchange_reached' => $exchangeReached,
    'code_index' => $input['worker'],
    'code_hash' => hash('sha256', $input['code']),
], JSON_THROW_ON_ERROR));
