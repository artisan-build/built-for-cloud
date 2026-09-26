<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\CompleteAsymmetricEnrollment;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\AsymmetricEnrollmentUnavailable;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid asymmetric enrollment worker input.\n");
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
        // The parent PostgreSQL lane owns the migrated schema shared by every worker.
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('built-for-cloud.manifest', TestCase::manifestForTests());
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
        $app['config']->set('built-for-cloud.credentials.app_purposes', [
            'reel.application.signing' => CredentialPurpose::Signing->value,
        ]);
    }

    /** @param array<string, mixed> $input @return array<string, mixed> */
    public function runProbe(array $input): array
    {
        parent::setUp();
        DB::statement("set application_name = 'bfc-asymmetric-enrollment-worker-".(int) $input['worker']."'");
        DB::statement("set lock_timeout = '10s'");
        $scope = new BoundCredentialScope(
            (string) $input['app_purpose'],
            new Subject(SubjectType::from((string) $input['subject_type']), (string) $input['subject_ref']),
            (string) $input['installation'],
            (string) $input['application'],
            (string) $input['audience'],
        );

        try {
            if ($input['operation'] === 'complete') {
                $result = app(CompleteAsymmetricEnrollment::class)(
                    (string) $input['code'],
                    $scope,
                    new Rs256PublicKey((string) $input['public_key']),
                );

                return ['outcome' => 'completed', 'credential_id' => $result->credentialId];
            }

            $result = app(RotateCredential::class)(
                (string) $input['source_id'],
                new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true),
            );

            return ['outcome' => 'reissued', 'credential_id' => $result?->mint->summary->id];
        } catch (AsymmetricEnrollmentUnavailable|RotationRefused $refused) {
            return ['outcome' => 'refused', 'class' => $refused::class];
        }
    }
};

try {
    fwrite(STDOUT, json_encode($case->runProbe($input), JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
