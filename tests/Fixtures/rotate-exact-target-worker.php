<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOwnership;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\ExactCredentialTarget;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

/**
 * The second ROTATING process for the exact-target lock claim.
 *
 * It rotates one credential under an exact purpose/subject/kind/ownership
 * predicate while the parent test holds that row's lock, so the parent can
 * retarget the row and commit while this process is blocked on
 * `lockForUpdate()`. Whatever this process reports is therefore the answer
 * the predicate gives on the row AS OF LOCK ACQUISITION — which is the one
 * thing an in-process test cannot observe.
 */
$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid rotate exact-target worker input.\n");
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
        // The parent PostgreSQL lane owns the migrated schema.
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
        $app['config']->set('queue.default', 'sync');
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array{outcome: string, refusal?: string, message?: string, replacement_id?: string}
     */
    public function runProbe(array $input): array
    {
        parent::setUp();

        DB::connection()->statement("set application_name = 'bfc-rotate-exact-target-worker'");

        $target = new ExactCredentialTarget(
            purpose: CredentialPurpose::from((string) $input['purpose']),
            subject: new Subject(
                SubjectType::from((string) $input['subject_type']),
                (string) $input['subject_ref'],
            ),
            kind: CredentialKind::from((string) $input['kind']),
            ownership: CredentialOwnership::Installation,
        );

        try {
            $result = app(RotateCredential::class)((string) $input['credential_id'], new RotateOptions(target: $target));
        } catch (Throwable $refusal) {
            return [
                'outcome' => 'refused',
                'refusal' => $refusal::class,
                'message' => $refusal->getMessage(),
            ];
        }

        return [
            'outcome' => 'rotated',
            'replacement_id' => (string) $result?->mint->summary->id,
        ];
    }
};

try {
    fwrite(STDOUT, json_encode($case->runProbe($input), JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
