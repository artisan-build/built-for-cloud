<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\ExchangeLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid credential authorization worker input.\n");
    exit(2);
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    protected function defineDatabaseMigrations(): void
    {
        // The parent PostgreSQL lane owns the shared migrated schema.
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $environment = static fn (string $name, string $default): string => (($value = getenv($name)) === false ? $default : $value);
        $app['config']->set('database.connections.pgsql_testing', [
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
            'sslmode' => $environment('PGSQL_TESTING_SSLMODE', 'prefer'),
        ]);
        $app['config']->set('database.default', 'pgsql_testing');
        $app['config']->set('built-for-cloud.credentials.declaration', DeviceFlowDeclaration::class);
        $app['config']->set('built-for-cloud.credentials.app_purposes', ['test.device' => CredentialPurpose::Consumption->value, 'test.loopback' => CredentialPurpose::Consumption->value]);
        $app['config']->set('built-for-cloud.ui.credential_purposes', ['test.device', 'test.loopback']);
        $app['config']->set('built-for-cloud.managed.client_secret', 'fixture-secret');
    }

    /** @param array<string, mixed> $input @return array<string, mixed> */
    public function runProbe(array $input): array
    {
        parent::setUp();
        DB::statement("set application_name = 'bfc-credential-authorization-worker-".(int) $input['worker']."'");
        DB::statement("set lock_timeout = '10s'");
        $subject = new Subject(SubjectType::from((string) $input['subject_type']), (string) $input['subject_ref']);
        DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
            (string) $input['app_purpose'],
            new BoundCredentialScope(
                (string) $input['app_purpose'],
                $subject,
                (string) $input['installation'],
                (string) $input['application'],
                (string) $input['audience'],
            ),
            CredentialAuthorizationOwnership::from((string) $input['ownership']),
            [],
            null,
            600,
            5,
        )];
        DeviceFlowDeclaration::$resolvedSubject = $subject;

        try {
            if ($input['operation'] === 'offboard') {
                app(OffboardSubject::class)(new OffboardOptions($subject->type, $subject->ref));

                return ['outcome' => 'offboarded'];
            }

            if ($input['operation'] === 'managed_denial') {
                $user = User::query()->findOrFail((string) $input['user_id']);
                $connection = ManagedAuthConnection::current();
                app(ManagedMembershipResponses::class)->applyConfirmation(
                    $connection,
                    $user,
                    new ManagedAuthConfirmation(
                        (string) $user->scalpels_id,
                        'removed',
                        'active',
                        'member',
                        2,
                        2,
                        new DateTimeImmutable((string) $input['now']),
                    ),
                );

                return ['outcome' => 'denied'];
            }

            $user = User::query()->findOrFail((string) $input['user_id']);
            $request = Request::create('/credential-authorization-worker', 'POST');
            $request->setUserResolver(static fn (): User => $user);
            $token = $input['flow'] === 'device'
                ? app(PollDeviceAuthorization::class)($request, (string) $input['code'])
                : app(ExchangeLoopbackAuthorization::class)(
                    $request,
                    (string) $input['code'],
                    (string) $input['redirect_uri'],
                    (string) $input['verifier'],
                );

            return ['outcome' => 'success', 'credential_id' => $token->credentialId];
        } catch (CredentialAuthorizationRefused $refused) {
            return ['outcome' => $refused->error];
        }
    }
};

try {
    fwrite(STDOUT, json_encode($case->runProbe($input), JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
