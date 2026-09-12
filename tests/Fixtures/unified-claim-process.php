<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Application;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$phase = $argv[1] ?? '';
$database = $argv[2] ?? '';
$value = $argv[3] ?? '';

if (! in_array($phase, ['setup', 'exchange', 'inspect', 'verify'], true) || $database === '') {
    fwrite(STDERR, "Invalid unified claim process arguments.\n");
    exit(2);
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite', [
            'driver' => 'sqlite',
            'database' => $_SERVER['BFC_CLAIM_DATABASE'],
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('c', 32)));
    }

    /** @return array<string, mixed> */
    public function runProbe(string $phase, string $value): array
    {
        parent::setUp();

        if ($phase === 'setup') {
            $this->artisan('migrate:fresh', ['--force' => true])->run();
            $plain = bin2hex(random_bytes(32));
            OnboardingToken::query()->create([
                'id' => (string) Str::uuid(),
                'email' => $value.'@fresh-process.test',
                'scope' => $value,
                'token_hash' => OnboardingToken::hashToken($plain),
                'expires_at' => now()->addHour(),
            ]);

            return ['claim_code' => $plain];
        }

        if ($phase === 'exchange') {
            $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $value]);

            return ['status' => $response->getStatusCode(), 'body' => $response->json()];
        }

        if ($phase === 'verify') {
            $response = $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$value]);

            return ['status' => $response->getStatusCode(), 'body' => $response->json()];
        }

        $code = OnboardingToken::query()
            ->where('token_hash', OnboardingToken::hashToken($value))
            ->sole();
        $credential = $code->durable_credential_id === null
            ? null
            : Credential::query()->findOrFail($code->durable_credential_id);

        return [
            'scope' => $code->scope,
            'consumed' => $code->consumed_at !== null,
            'durable_token_id' => $code->durable_token_id,
            'durable_store' => $code->durable_store?->value,
            'durable_credential_id' => $code->durable_credential_id,
            'api_tokens' => ApiToken::query()->count(),
            'credentials' => Credential::query()->count(),
            'credential' => $credential === null ? null : [
                'id' => $credential->id,
                'kind' => $credential->kind->value,
                'subject_type' => $credential->subject_type->value,
                'subject_ref' => $credential->subject_ref,
                'abilities' => $credential->abilities,
                'secret_hash' => $credential->secret_hash,
            ],
        ];
    }
};

$_SERVER['BFC_CLAIM_DATABASE'] = $database;

try {
    $result = $case->runProbe($phase, $value);
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
