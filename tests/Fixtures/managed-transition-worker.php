<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionClient;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Str;

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
    'built-for-cloud' => ['managed' => ['client_secret' => 'transition-secret']],
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

try {
    if ($input['mode'] === 'active-slot') {
        $installationId = $input['installation_id'] ?? 'race-installation';
        $organizationId = $input['organization_id'] ?? 'race-organization';
        if ($input['application_check']) {
            $owner = User::query()->findOrFail($input['owner_id']);
            $calls = 0;
            $http = new Factory;
            $http->fake(function (ClientRequest $request) use ($http, $input, $installationId, $organizationId, &$calls): mixed {
                $calls++;
                $requestBody = json_decode($request->body(), true, flags: JSON_THROW_ON_ERROR);

                return $http->response([
                    'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                    'issuer' => 'https://issuer.example.test',
                    'connection_id' => 'race-connection',
                    'organization_id' => $organizationId,
                    'installation_id' => $installationId,
                    'authority_generation' => 7,
                    'roster_version' => 41,
                    'response_sequence' => 73,
                    'responded_at' => '2026-09-11T12:00:01+00:00',
                    'transition_request_id' => $requestBody['transition_request_id'],
                    'transition_id' => 'authority-'.$input['application_name'],
                    'direction' => $requestBody['direction'],
                    'status' => 'prepared',
                    'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
                    'roster_total' => 1,
                ]);
            });
            $transition = (new ManagedTransitions($http))->prepare(
                $owner,
                ManagedTransitionDirection::from($input['direction']),
            );
            $result = ['result' => 'inserted', 'status' => $transition->status->value, 'calls' => $calls];
        } else {
            $body = json_encode([
                'connection_id' => 'race-connection',
                'installation_id' => $installationId,
                'direction' => $input['direction'],
                'transition_request_id' => $input['request_id'],
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            ManagedTransition::createActive([
                'id' => (string) Str::uuid(),
                'initiated_by_user_id' => '1',
                'direction' => ManagedTransitionDirection::from($input['direction']),
                'status' => ManagedTransitionStatus::Preparing,
                'issuer' => 'https://issuer.example.test',
                'connection_id' => 'race-connection',
                'organization_id' => $organizationId,
                'installation_id' => $installationId,
                'authority_base_url' => 'https://transition-authority.example.test',
                'authority_ca_bundle' => null,
                'client_credential_reference' => 'built-for-cloud.managed.client_secret',
                'mode_before' => $input['direction'] === 'adopt' ? 'standalone' : 'managed',
                'mode_after' => $input['direction'] === 'adopt' ? 'managed' : 'standalone',
                'generation_before' => 7,
                'generation_after' => 8,
                'transition_request_id' => $input['request_id'],
                'prepare_request_body' => $body,
                'prepare_body_digest' => hash('sha256', $body),
            ]);
            $result = ['result' => 'inserted', 'status' => 'preparing', 'calls' => 0];
        }
    } elseif (in_array($input['mode'], ['production-stage', 'production-commit', 'production-abandon'], true)) {
        $transition = ManagedTransition::query()->findOrFail($input['transition_id']);
        $calls = 0;
        $http = new Factory;
        $http->fake(function (ClientRequest $request) use ($http, $transition, &$calls): mixed {
            $calls++;
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            $status = str_ends_with($path, '/abandon') ? 'abandoned' : 'staged';
            $payload = [
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'issuer' => $transition->issuer,
                'connection_id' => $transition->connection_id,
                'organization_id' => $transition->organization_id,
                'installation_id' => $transition->installation_id,
                'authority_generation' => $transition->generation_before,
                'roster_version' => $transition->roster_version,
                'response_sequence' => 73,
                'responded_at' => '2026-09-11T12:00:01+00:00',
                'transition_id' => $transition->transition_id,
                'status' => $status,
            ];

            if ($status === 'staged') {
                $payload += [
                    'direction' => $transition->direction->value,
                    'roster_cutoff_at' => $transition->roster_cutoff_at,
                    'local_commit_receipt' => null,
                    'acknowledged_at' => null,
                ];
            }

            return $http->response($payload);
        });
        $service = new ManagedTransitions($http);

        if ($input['mode'] === 'production-stage') {
            $completed = $service->stage($transition);
        } elseif ($input['mode'] === 'production-commit') {
            $effects = 0;
            $completed = $service->commit($transition, static function () use (&$effects): void {
                $effects++;
                if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed) === null) {
                    throw new RuntimeException('Production commit worker could not switch mode.');
                }
            });
        } else {
            $owner = User::query()->findOrFail($input['owner_id']);
            $session = new Store('p4b-transition-worker', new ArraySessionHandler(120));
            $session->start();
            $session->put(StandaloneAccess::SESSION_VERSION_KEY, $owner->auth_session_version);
            $request = Request::create('/abandon', 'POST');
            $request->setLaravelSession($session);
            $request->setUserResolver(static fn (): User => $owner);
            $completed = $service->abandon($request, $transition);
        }

        $result = ['result' => $completed->status->value, 'calls' => $calls, 'effects' => $effects ?? 0];
    } elseif ($input['mode'] === 'production-recover') {
        $transition = ManagedTransition::query()->findOrFail($input['transition_id']);
        $calls = [];
        $http = new Factory;
        $http->fake(function (ClientRequest $request) use ($http, $transition, $input, &$calls): mixed {
            $path = (string) parse_url($request->url(), PHP_URL_PATH);
            $calls[] = ['path' => $path, 'body' => $request->body()];
            $generation = $input['authority_status'] === 'acknowledged'
                ? $transition->generation_after
                : $transition->generation_before;
            $binding = [
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'issuer' => $transition->issuer,
                'connection_id' => $transition->connection_id,
                'organization_id' => $transition->organization_id,
                'installation_id' => $transition->installation_id,
                'authority_generation' => $generation,
                'roster_version' => $transition->roster_version ?? 41,
                'response_sequence' => 73,
                'responded_at' => '2026-09-11T12:00:01+00:00',
            ];

            if (str_contains($path, '/transition-requests/')) {
                $prepared = $input['authority_status'] === 'prepared';
                $payload = [
                    ...$binding,
                    'transition_request_id' => $transition->transition_request_id,
                    'transition_id' => $prepared ? 'authority-transition-recovered' : null,
                    'status' => $prepared ? 'prepared' : null,
                ];
            } elseif ($path === '/managed-transition/v1/transitions') {
                $payload = [
                    ...$binding,
                    'transition_request_id' => $transition->transition_request_id,
                    'transition_id' => 'authority-transition-recovered',
                    'direction' => $transition->direction->value,
                    'status' => 'prepared',
                    'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
                    'roster_total' => 1,
                ];
            } elseif (str_ends_with($path, '/stage')) {
                $payload = [
                    ...$binding,
                    'transition_id' => $transition->transition_id,
                    'status' => 'staged',
                    'roster_cutoff_at' => $transition->roster_cutoff_at,
                ];
            } elseif (str_ends_with($path, '/ack')) {
                $payload = [
                    ...$binding,
                    'authority_generation' => $transition->generation_after,
                    'transition_id' => $transition->transition_id,
                    'status' => 'acknowledged',
                    'generation_after' => $transition->generation_after,
                    'local_commit_receipt' => $transition->local_commit_receipt,
                    'acknowledged_at' => '2026-09-11T12:05:00+00:00',
                ];
            } else {
                $status = $input['authority_status'];
                $payload = [
                    ...$binding,
                    'transition_id' => $transition->transition_id,
                    'direction' => $transition->direction->value,
                    'status' => $status,
                    'roster_cutoff_at' => $transition->roster_cutoff_at,
                    'local_commit_receipt' => $status === 'acknowledged' ? $transition->local_commit_receipt : null,
                    'acknowledged_at' => $status === 'acknowledged' ? '2026-09-11T12:05:00+00:00' : null,
                ];
            }

            return $http->response($payload);
        });
        $recovered = (new ManagedTransitions($http))->recover($transition);
        $result = [
            'result' => $recovered->status->value,
            'calls' => $calls,
            'stage_key' => $recovered->stage_idempotency_key,
            'ack_key' => $recovered->ack_idempotency_key,
        ];
    } else {
        $transition = ManagedTransition::query()->findOrFail($input['transition_id']);
        $decoded = json_decode($transition->prepare_request_body, true, flags: JSON_THROW_ON_ERROR);
        ksort($decoded);
        $rebuilt = json_encode($decoded, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $sent = null;
        $http = new Factory;
        $http->fake(function (ClientRequest $request) use (&$sent, $transition, $http): mixed {
            $sent = $request->body();
            $requestBody = json_decode($request->body(), true, flags: JSON_THROW_ON_ERROR);
            $payload = [
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'issuer' => $transition->issuer,
                'connection_id' => $transition->connection_id,
                'organization_id' => $transition->organization_id,
                'installation_id' => $transition->installation_id,
                'authority_generation' => $transition->generation_before,
                'roster_version' => 41,
                'response_sequence' => 73,
                'responded_at' => '2026-09-11T12:00:01+00:00',
                'transition_request_id' => $requestBody['transition_request_id'],
                'transition_id' => 'authority-transition-replayed',
                'direction' => $requestBody['direction'],
                'status' => 'prepared',
                'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
                'roster_total' => 1,
            ];

            return $http->response($payload, 200, ['Content-Type' => 'application/json']);
        });
        (new ManagedTransitionClient($http, $transition))->prepare();
        $result = [
            'result' => 'sent',
            'persisted' => $transition->prepare_request_body,
            'sent' => $sent,
            'rebuilt' => $rebuilt,
        ];
    }
} catch (ManagedAuthRefused $exception) {
    $causes = [];
    for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
        $causes[] = ['class' => $cause::class, 'message' => $cause->getMessage()];
    }
    $result = [
        'result' => 'refused',
        'class' => $exception::class,
        'message' => $exception->getMessage(),
        'calls' => $calls ?? null,
        'effects' => $effects ?? 0,
        'causes' => $causes,
    ];
} catch (Throwable $exception) {
    $causes = [];
    for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
        $causes[] = ['class' => $cause::class, 'message' => $cause->getMessage()];
    }
    $result = ['result' => 'database-refused', 'class' => $exception::class, 'causes' => $causes];
}

fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
