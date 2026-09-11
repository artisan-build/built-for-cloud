<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
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
$connection->statement("set application_name = '".str_replace("'", "''", $input['application_name'])."'");
$managedConnection = new ManagedAuthConnection(
    'https://issuer.example.test',
    'connection-fixture',
    'organization-fixture',
    'installation-fixture',
    7,
    'https://127.0.0.1:1',
    'unused',
    null,
);
$exchange = new ManagedAuthExchange(
    $input['subject'],
    'membership-'.$input['subject'],
    'active',
    'active',
    'owner',
    'Concurrent '.$input['subject'],
    $input['subject'].'@example.test',
    true,
    20,
    20,
    new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
);

try {
    $responses = new ManagedMembershipResponses(
        new ManagedIdentityUpsert,
        new ManagedAuthClient(new Factory),
    );

    if ($input['mode'] === 'without-application-check') {
        $user = (new ManagedIdentityUpsert)->upsert($managedConnection, $exchange);
        $result = ['result' => 'seated', 'id' => $user->getKey()];
    } elseif ($input['mode'] === 'confirmation') {
        $user = ArtisanBuild\BuiltForCloud\User::query()->where('scalpels_id', $input['subject'])->sole();
        $allowed = $responses->applyConfirmation(
            $managedConnection,
            $user,
            new ManagedAuthConfirmation(
                $input['subject'],
                'active',
                'active',
                'owner',
                20,
                20,
                new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
            ),
        );
        $result = ['result' => $allowed ? 'seated' : 'denied', 'id' => $user->getKey()];
    } else {
        $user = $responses->applyExchange($managedConnection, $exchange);
        $result = ['result' => 'seated', 'id' => $user?->getKey()];
    }
} catch (ManagedAuthRefused $exception) {
    $causes = [];

    for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
        $causes[] = ['class' => $cause::class, 'message' => $cause->getMessage()];
    }

    $result = [
        'result' => 'refused',
        'message' => $exception->getMessage(),
        'causes' => $causes,
    ];
}

fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
