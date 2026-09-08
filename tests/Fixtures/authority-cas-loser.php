<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\AuthorityState;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;

require dirname(__DIR__, 2).'/vendor/autoload.php';

$environment = static fn (string $name, string $default): string => (($value = getenv($name)) === false ? $default : $value);
$connection = [
    'driver' => 'pgsql',
    'host' => $environment('PGSQL_TESTING_HOST', '127.0.0.1'),
    'port' => $environment('PGSQL_TESTING_PORT', '5432'),
    'database' => $environment('PGSQL_TESTING_DATABASE', 'bfc_testing'),
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
        'default' => 'pgsql_testing_probe',
        'connections' => ['pgsql_testing_probe' => $connection],
    ],
]));
$capsule = new Capsule($container);
$capsule->addConnection($connection, 'pgsql_testing_probe');
$container->instance('db', $capsule->getDatabaseManager());
Facade::setFacadeApplication($container);

$applicationName = $argv[1] ?? 'bfc-authority-cas-loser';
DB::connection('pgsql_testing_probe')->selectOne(
    "select set_config('application_name', ?, false)",
    [$applicationName],
);

fwrite(STDOUT, "ready\n");
fflush(STDOUT);

$result = InstallationAuthority::change(
    AuthorityState::fromRaw(AuthorityMode::Standalone->value, 1),
    AuthorityMode::Managed,
    'pgsql_testing_probe',
);

fwrite(STDOUT, json_encode([
    'mode' => $result?->mode?->value,
    'generation' => $result?->generation,
], JSON_THROW_ON_ERROR));
