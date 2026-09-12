<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$phase = $argv[1] ?? '';
$database = $argv[2] ?? '';
$value = json_decode($argv[3] ?? '[]', true);

if (! in_array($phase, ['setup', 'mint', 'activate', 'verify', 'inspect'], true)
    || $database === ''
    || ! is_array($value)) {
    fwrite(STDERR, "Invalid personal hmac process arguments.\n");
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
            'database' => $_SERVER['BFC_PERSONAL_HMAC_DATABASE'],
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('built-for-cloud.credentials.declaration', SelfServicePolicyDeclaration::class);
        $app['config']->set('built-for-cloud.hmac.audience', 'https://personal-hmac-process.example');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('p', 32)));
    }

    /**
     * @param  array<string, mixed>  $value
     * @return array<string, mixed>
     */
    public function runProbe(string $phase, array $value): array
    {
        parent::setUp();

        if ($phase === 'setup') {
            $this->artisan('migrate:fresh', ['--force' => true])->run();

            $user = User::query()->create([
                'name' => 'Personal HMAC User',
                'email' => 'personal-hmac@example.test',
                'password' => Hash::make('correct horse battery staple'),
            ]);
            $adminToken = 'personal-hmac-admin-'.bin2hex(random_bytes(16));

            ApiToken::query()->create([
                'name' => 'personal-hmac-activation',
                'token_hash' => hash('sha256', $adminToken),
                'abilities' => [Scope::Admin->value],
            ]);

            return [
                'authority' => InstallationAuthority::current()->mode?->value,
                'user_id' => (string) $user->getKey(),
                'admin_token' => $adminToken,
            ];
        }

        if ($phase === 'mint') {
            SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];

            $login = $this->post('/bfc/login', [
                'email' => 'personal-hmac@example.test',
                'password' => 'correct horse battery staple',
            ]);
            $response = $this->postJson('/bfc/me/credentials', [
                'name' => 'fresh-process-signing',
                'kind' => CredentialKind::Hmac->value,
                'subject_ref' => 'crafted-subject',
                'user_id' => 'crafted-user',
            ]);

            return [
                'login_status' => $login->getStatusCode(),
                'status' => $response->getStatusCode(),
                'body' => $response->json(),
            ];
        }

        if ($phase === 'activate') {
            $response = $this->postJson('/bfc/credentials/'.$value['key_id'].'/activate', [
                'delivery_fingerprint' => $value['delivery_fingerprint'],
            ], [
                'Authorization' => 'Bearer '.$value['admin_token'],
            ]);

            return ['status' => $response->getStatusCode(), 'body' => $response->json()];
        }

        if ($phase === 'verify') {
            Route::post('/personal-hmac/{user}', function (Request $request): array {
                return ['credential_id' => $request->attributes->get('bfc.hmac_credential_id')];
            })->middleware('bfc.hmac');

            $body = '{"event":"fresh-process"}';
            $envelope = new HmacEnvelope(
                keyId: $value['key_id'],
                eventType: 'self-service.test',
                timestamp: now()->getTimestamp(),
                nonce: bin2hex(random_bytes(16)),
                audience: (string) config('built-for-cloud.hmac.audience'),
            );
            $header = $envelope->headerValue(hash_hmac(
                'sha256',
                $envelope->canonical($body),
                $value['signing_key'],
            ));
            $response = $this->call('POST', '/personal-hmac/'.$value['user_id'], server: [
                'HTTP_'.str_replace('-', '_', strtoupper(HmacEnvelope::HEADER)) => $header,
                'CONTENT_TYPE' => 'application/json',
            ], content: $body);

            return ['status' => $response->getStatusCode(), 'body' => $response->json()];
        }

        $credential = Credential::query()->findOrFail($value['key_id']);

        return [
            'kind' => $credential->kind->value,
            'status' => $credential->status->value,
            'subject_ref' => $credential->subject_ref,
            'user_id' => $credential->user_id,
            'ciphertext_contains_key' => str_contains((string) $credential->secret_ciphertext, $value['signing_key']),
            'decrypts_to_delivered_key' => app(HmacKeyring::class)->decrypt(
                (string) $credential->secret_ciphertext,
                $credential->secret_key_version,
            ) === $value['signing_key'],
            'last_used_at' => $credential->last_used_at?->toIso8601String(),
        ];
    }
};

$_SERVER['BFC_PERSONAL_HMAC_DATABASE'] = $database;

try {
    $result = $case->runProbe($phase, $value);
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
