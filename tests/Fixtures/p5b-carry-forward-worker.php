<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$scenario = $argv[1] ?? '';
$phase = $argv[2] ?? '';
$database = $argv[3] ?? '';
$payload = json_decode(stream_get_contents(STDIN), true);

if (! in_array($scenario, [
    'ownership-claim',
    'ownership-remint',
    'dashboard',
    'offboard',
    'expiry',
    'operator-routes',
    'client-identity',
    'mcp',
], true) || ! in_array($phase, ['setup', 'request', 'command', 'verify', 'inspect'], true)
    || $database === '' || ! is_array($payload)) {
    fwrite(STDERR, "Invalid P5b carry-forward process arguments.\n");
    exit(2);
}

$_SERVER['BFC_P5B_DATABASE'] = $database;

/**
 * Evidence harness limit: this proves committed SQLite persistence across a
 * fresh Testbench application boot and request/command process only. It does
 * not prove PostgreSQL foreign-key behavior, real socket transport, or either
 * live rung.
 */
$case = new class('testProbe') extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.guards.bfc', ['driver' => 'bfc', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite', [
            'driver' => 'sqlite',
            'database' => $_SERVER['BFC_P5B_DATABASE'],
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('queue.default', 'sync');
        $app['config']->set('built-for-cloud.console.enabled', true);
        $app['config']->set('built-for-cloud.client_identity.observe_unauthenticated', true);
        $app['config']->set('built-for-cloud.client_identity.max_observations', 10);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('built-for-cloud.product', 'P5b process proof');
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('f', 32)));
    }

    public function runProbe(string $scenario, string $phase, array $payload): array
    {
        parent::setUp();

        if ($phase === 'setup') {
            $this->artisan('migrate:fresh', ['--force' => true])->run();
        }

        $result = match ($scenario) {
            'ownership-claim' => $this->ownershipClaim($phase, $payload),
            'ownership-remint' => $this->ownershipRemint($phase, $payload),
            'dashboard' => $this->dashboard($phase, $payload),
            'offboard' => $this->offboard($phase, $payload),
            'expiry' => $this->expiry($phase, $payload),
            'operator-routes' => $this->operatorRoutes($phase, $payload),
            'client-identity' => $this->clientIdentity($phase, $payload),
            'mcp' => $this->mcp($phase, $payload),
        };

        return [
            'pid' => getmypid(),
            'phase' => $phase,
            'scenario' => $scenario,
            ...$result,
        ];
    }

    private function ownershipClaim(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            OwnershipClaim::query()->create([
                'id' => $payload['claim_id'],
                'token_hash' => $payload['claim_hash'],
            ]);

            return ['claim_id' => $payload['claim_id']];
        }

        if ($phase === 'request') {
            $response = $this->postJson('/bfc/ownership/claim', ['token' => $payload['claim_secret']]);

            return ['status' => $response->getStatusCode(), 'response_keys' => array_keys($response->json())];
        }

        $ownership = Ownership::query()->sole();
        $claim = OwnershipClaim::query()->findOrFail($payload['claim_id']);
        $credential = Credential::query()->findOrFail($ownership->owner_credential_id);

        return [
            'ownership_count' => Ownership::query()->count(),
            'owner_credential_id' => $ownership->owner_credential_id,
            'claim_id' => $claim->id,
            'claim_consumed' => $claim->consumed_at !== null,
            'credential_count' => Credential::query()->count(),
            'credential' => $this->credentialState($credential),
        ];
    }

    private function ownershipRemint(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            $this->createCredential($payload['old_owner']);
            $this->createCredential($payload['other_owner']);
            Ownership::query()->create([
                'id' => $payload['ownership_id'],
                'owner_credential_id' => $payload['old_owner']['id'],
                'webhook_secret' => $payload['webhook_secret'],
            ]);

            return ['ownership_id' => $payload['ownership_id']];
        }

        if ($phase === 'command') {
            $exit = $this->artisan('bfc:ownership:remint-owner-token', [
                '--execute' => true,
                '--hash' => $payload['new_hash'],
            ])->run();

            return ['exit' => $exit];
        }

        $ownership = Ownership::query()->sole();

        return [
            'ownership_count' => Ownership::query()->count(),
            'ownership_id' => $ownership->id,
            'owner_credential_id' => $ownership->owner_credential_id,
            'webhook_secret' => $ownership->webhook_secret,
            'credentials' => Credential::query()->orderBy('id')->get()->map(fn (Credential $credential): array => $this->credentialState($credential))->all(),
        ];
    }

    private function dashboard(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            foreach ($payload['credentials'] as $credential) {
                $this->createCredential($credential);
            }

            return ['credential_ids' => array_column($payload['credentials'], 'id')];
        }

        if ($phase === 'request') {
            $statuses = [];

            foreach ($payload['bearers'] as $name => $bearer) {
                $statuses[$name] = $this->getJson('/bfc/console/vitals', [
                    'Authorization' => 'Bearer '.$bearer,
                ])->getStatusCode();
            }

            return ['statuses' => $statuses];
        }

        return [
            'credentials' => Credential::query()->orderBy('id')->get()->map(fn (Credential $credential): array => $this->credentialState($credential))->all(),
            'audit' => $this->auditState(),
        ];
    }

    private function offboard(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            User::query()->create([
                'id' => $payload['user_id'],
                'name' => 'P5b User',
                'email' => $payload['email'],
                'password' => Hash::make('unused process password'),
            ]);

            foreach ($payload['credentials'] as $credential) {
                $this->createCredential($credential);
            }

            return ['user_id' => $payload['user_id']];
        }

        if ($phase === 'request') {
            $response = $this->postJson('/bfc/subjects/offboard', [
                'subject_type' => SubjectType::ExternalConsumer->value,
                'subject_ref' => $payload['target_subject'],
            ], ['Authorization' => 'Bearer '.$payload['operator_secret']]);

            return ['status' => $response->getStatusCode(), 'body' => $response->json()];
        }

        if ($phase === 'verify') {
            Route::get('/p5b-auth-probe', static fn (): array => ['ok' => true])->middleware('auth:bfc');
            $statuses = [];

            foreach ($payload['bearers'] as $name => $bearer) {
                $statuses[$name] = $this->getJson('/p5b-auth-probe', [
                    'Authorization' => 'Bearer '.$bearer,
                ])->getStatusCode();
            }

            return ['statuses' => $statuses];
        }

        return [
            'credentials' => Credential::query()->orderBy('id')->get()->map(fn (Credential $credential): array => $this->credentialState($credential))->all(),
            'audit' => $this->auditState(),
        ];
    }

    private function expiry(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            $this->createCredential($payload['credential']);
            return ['credential_id' => $payload['credential']['id']];
        }

        if ($phase === 'command') {
            return ['exit' => $this->artisan('bfc:credentials:warn-expiring')->run()];
        }

        $credential = Credential::query()->findOrFail($payload['credential_id']);

        return [
            'credential_id' => $credential->id,
            'expires_at' => $credential->expires_at?->format('Y-m-d H:i:s'),
            'audit' => $this->auditState(),
        ];
    }

    private function operatorRoutes(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            foreach ($payload['credentials'] as $credential) {
                $this->createCredential($credential);
            }

            OwnershipClaim::query()->create([
                'id' => $payload['initial_claim_id'],
                'token_hash' => $payload['initial_claim_hash'],
            ]);
            Ownership::query()->create([
                'id' => $payload['ownership_id'],
                'owner_credential_id' => $payload['owner_credential_id'],
                'pending_claim_id' => $payload['initial_claim_id'],
            ]);

            return ['ownership_id' => $payload['ownership_id']];
        }

        if ($phase === 'request') {
            $authorization = static fn (string $bearer): array => ['Authorization' => 'Bearer '.$bearer];

            return ['statuses' => [
                'cancel_wrong' => $this->postJson('/bfc/ownership/cancel-transfer', [], $authorization($payload['cancel_wrong']))->getStatusCode(),
                'cancel_exact' => $this->postJson('/bfc/ownership/cancel-transfer', [], $authorization($payload['release_exact']))->getStatusCode(),
                'release_wrong' => $this->postJson('/bfc/ownership/release', [], $authorization($payload['release_wrong']))->getStatusCode(),
                'release_exact' => $this->postJson('/bfc/ownership/release', [], $authorization($payload['release_exact']))->getStatusCode(),
                'issue_wrong' => $this->postJson('/bfc/onboarding/issue', [
                    'email' => $payload['issue_email'],
                    'ttl_seconds' => 3600,
                ], $authorization($payload['issue_wrong']))->getStatusCode(),
                'issue_exact' => $this->postJson('/bfc/onboarding/issue', [
                    'email' => $payload['issue_email'],
                    'ttl_seconds' => 3600,
                ], $authorization($payload['issue_exact']))->getStatusCode(),
                'observations_wrong' => $this->getJson('/bfc/client-observations', $authorization($payload['observations_wrong']))->getStatusCode(),
                'observations_exact' => $this->getJson('/bfc/client-observations', $authorization($payload['observations_exact']))->getStatusCode(),
            ]];
        }

        $ownership = Ownership::query()->findOrFail($payload['ownership_id']);
        $initial = OwnershipClaim::query()->findOrFail($payload['initial_claim_id']);
        $pending = OwnershipClaim::query()->findOrFail($ownership->pending_claim_id);
        $issued = OnboardingToken::query()->sole();

        return [
            'initial_claim_consumed' => $initial->consumed_at !== null,
            'pending_claim_id' => $ownership->pending_claim_id,
            'pending_claim_is_new' => $ownership->pending_claim_id !== $initial->id,
            'pending_claim_consumed' => $pending->consumed_at !== null,
            'claim_count' => OwnershipClaim::query()->count(),
            'onboarding_count' => OnboardingToken::query()->count(),
            'onboarding' => [
                'email' => $issued->email,
                'scope' => $issued->scope,
                'consumed' => $issued->consumed_at !== null,
            ],
            'credentials' => Credential::query()->orderBy('id')->get()->map(fn (Credential $credential): array => $this->credentialState($credential))->all(),
            'audit' => $this->auditState(),
        ];
    }

    private function clientIdentity(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            $this->createCredential($payload['credential']);

            return ['credential_id' => $payload['credential']['id']];
        }

        if ($phase === 'request') {
            $headers = ['Authorization' => 'Bearer '.$payload['secret']];
            $authenticated = $this->getJson('/bfc/client-observations', [
                ...$headers,
                'X-BfC-Client-Id' => $payload['authenticated_identity'],
            ]);
            $unauthenticated = $this->getJson('/bfc/client-observations', [
                'X-BfC-Client-Id' => $payload['unauthenticated_identity'],
            ]);
            $read = $this->getJson('/bfc/client-observations', $headers);

            return [
                'statuses' => [
                    'authenticated' => $authenticated->getStatusCode(),
                    'unauthenticated' => $unauthenticated->getStatusCode(),
                    'read' => $read->getStatusCode(),
                ],
                'read_enabled' => $read->json('enabled'),
                'read_observations' => array_column($read->json('observations'), 'client_identity'),
            ];
        }

        $credential = Credential::query()->findOrFail($payload['credential_id']);
        $observations = app('db')->table('bfc_client_identity_observations')->orderBy('client_identity')->get();

        return [
            'credential' => $this->credentialState($credential),
            'observations' => $observations->map(static fn (object $row): array => [
                'client_identity' => $row->client_identity,
                'client_identity_hash' => $row->client_identity_hash,
                'observation_count' => (int) $row->observation_count,
                'first_seen' => $row->first_seen_at !== null,
                'last_seen' => $row->last_seen_at !== null,
            ])->all(),
        ];
    }

    private function mcp(string $phase, array $payload): array
    {
        if ($phase === 'setup') {
            foreach ($payload['credentials'] as $credential) {
                $this->createCredential($credential);
            }

            return ['credential_ids' => array_column($payload['credentials'], 'id')];
        }

        if ($phase === 'request') {
            Route::post('/mcp-probe', static function (Request $request): array {
                $credential = $request->user();
                $actorCredentialId = $request->attributes->get('bfc.actor_credential_id');
                $actor = is_string($actorCredentialId) && $actorCredentialId !== ''
                    ? AuditActor::operatorIntegration($actorCredentialId)
                    : null;

                return [
                    'principal_type' => is_object($credential) ? $credential::class : null,
                    'principal_id' => $credential instanceof Credential ? $credential->id : null,
                    'actor_token_id' => $request->attributes->get('bfc.actor_token_id'),
                    'actor_credential_id' => $actorCredentialId,
                    'audit_type' => $actor?->type->value,
                    'audit_ref' => $actor?->ref,
                    'authorization_scrubbed' => $request->header('Authorization') === null,
                ];
            })->middleware('bfc.mcp');

            $responses = [];

            foreach ($payload['bearers'] as $name => $bearer) {
                $response = $this->postJson('/mcp-probe', [], [
                    'Authorization' => 'Bearer '.$bearer,
                    'X-BfC-Client-Id' => 'p5b-mcp-'.$name,
                ]);
                $responses[$name] = ['status' => $response->getStatusCode(), 'body' => $response->json()];
            }

            return ['responses' => $responses];
        }

        return [
            'credentials' => Credential::query()->orderBy('id')->get()->map(fn (Credential $credential): array => $this->credentialState($credential))->all(),
        ];
    }

    private function createCredential(array $attributes): Credential
    {
        return Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'subject_type' => SubjectType::Application,
            'subject_ref' => 'p5b-default',
            'name' => 'p5b process credential',
            'abilities' => null,
            'status' => CredentialStatus::Active,
            ...$attributes,
        ]);
    }

    private function credentialState(Credential $credential): array
    {
        return [
            'id' => $credential->id,
            'kind' => $credential->kind->value,
            'subject_type' => $credential->subject_type->value,
            'subject_ref' => $credential->subject_ref,
            'name' => $credential->name,
            'abilities' => $credential->abilities,
            'user_id' => $credential->user_id,
            'secret_hash' => $credential->secret_hash,
            'status' => $credential->status->value,
            'revoked' => $credential->revoked_at !== null,
            'expires_at' => $credential->expires_at?->format('Y-m-d H:i:s'),
            'last_used' => $credential->last_used_at !== null,
            'client_identity' => $credential->client_identity,
            'client_identity_last_seen' => $credential->client_identity_last_seen_at !== null,
        ];
    }

    private function auditState(): array
    {
        return CredentialAuditEvent::query()->orderBy('created_at')->get()->map(static fn (CredentialAuditEvent $event): array => [
            'event' => $event->event->value,
            'credential_id' => $event->credential_id,
            'code_id' => $event->code_id,
            'actor_type' => $event->actor_type?->value,
            'actor_ref' => $event->actor_ref,
            'credential_expires_at' => $event->credential_expires_at?->format('Y-m-d H:i:s'),
        ])->all();
    }
};

try {
    $result = $case->runProbe($scenario, $phase, $payload);
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
