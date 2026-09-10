<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
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
$capsule->getDatabaseManager()->setDefaultConnection('pgsql_testing');
$capsule->setAsGlobal();
$capsule->bootEloquent();
Container::setInstance($container);
Facade::setFacadeApplication($container);
$connection = $capsule->getConnection('pgsql_testing');
$connection->statement("set application_name = '".str_replace("'", "''", $input['application_name'])."'");
$user = (new ManagedIdentityUpsert)->upsert(
    new ManagedAuthConnection(
        $input['issuer'],
        $input['connection_id'],
        'organization-fixture',
        'installation-fixture',
        7,
        'https://authority.example.test',
        'fixture-client-secret',
        null,
    ),
    new ManagedAuthExchange(
        $input['subject'],
        'membership-fixture',
        'active',
        'active',
        $input['role'] ?? 'member',
        $input['name'] ?? 'Managed Worker',
        $input['email'],
        true,
        8,
        13,
        new DateTimeImmutable('2026-09-10T12:00:00+00:00'),
    ),
);

fwrite(STDOUT, json_encode([
    'id' => $user->getKey(),
    'email' => $user->email,
    'original_contact_email' => $user->original_contact_email,
    'email_is_generated' => $user->email_is_generated,
    'email_conflict_at' => $user->email_conflict_at?->toAtomString(),
    'email_conflict_source' => $user->email_conflict_source,
], JSON_THROW_ON_ERROR));
