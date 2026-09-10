<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedHandoffClaim;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
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
]));
$capsule = new Capsule($container);
$capsule->addConnection($database, 'pgsql_testing');
$container->instance('db', $capsule->getDatabaseManager());
$capsule->setAsGlobal();
Facade::setFacadeApplication($container);
$connection = $capsule->getConnection('pgsql_testing');
$connection->statement("set application_name = 'bfc-p3a-claim-worker-".(int) $input['worker']."'");
$claimed = (new ManagedHandoffClaim)->consume(
    new ManagedAuthConnection(
        $input['issuer'],
        $input['connection_id'],
        $input['organization_id'],
        $input['installation_id'],
        $input['authority_generation'],
        $input['base_url'],
        '',
        null,
    ),
    $input['state'],
    $input['session_nonce'],
    CarbonImmutable::now(),
    'pgsql_testing',
);

fwrite(STDOUT, json_encode([
    'claimed' => $claimed,
    'exchange_reached' => $claimed,
    'code_index' => $input['worker'],
    'code_hash' => hash('sha256', $input['code']),
], JSON_THROW_ON_ERROR));
