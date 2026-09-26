<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid HMAC rewrap worker input.\n");
    exit(2);
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    protected function defineDatabaseMigrations(): void {}

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
    }

    /** @param array<string, mixed> $input @return array<string, mixed> */
    public function runProbe(array $input): array
    {
        parent::setUp();
        config()->set('app.key', (string) $input['new_key']);
        config()->set('app.previous_keys', [(string) $input['old_key']]);
        DB::statement("set application_name = 'bfc-hmac-rewrap-worker'");
        DB::statement("set lock_timeout = '10s'");
        $exit = Artisan::call('bfc:hmac:rewrap', ['--chunk' => 1]);

        return ['exit' => $exit, 'output' => Artisan::output()];
    }
};

try {
    fwrite(STDOUT, json_encode($case->runProbe($input), JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
