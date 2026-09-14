<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$phase = $argv[1] ?? '';
$database = $argv[2] ?? '';
$ready = $argv[3] ?? '';
$go = $argv[4] ?? '';

if (! in_array($phase, ['setup', 'install', 'inspect'], true) || $database === '') {
    fwrite(STDERR, "Invalid concurrent install probe arguments.\n");
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
            'database' => $_SERVER['BFC_INSTALL_DATABASE'],
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('i', 32)));
    }

    public function runProbe(string $phase, string $ready, string $go): int
    {
        parent::setUp();

        if ($phase === 'setup') {
            $this->artisan('migrate:fresh', ['--force' => true])->run();

            return 0;
        }

        if ($phase === 'inspect') {
            fwrite(STDOUT, (string) Credential::query()->count());

            return 0;
        }

        $waiting = false;
        DB::listen(static function (QueryExecuted $query) use (&$waiting, $ready, $go): void {
            if ($waiting || ! str_contains(strtolower($query->sql), 'from "credentials"')) {
                return;
            }

            $waiting = true;
            $readyPipe = fopen($ready, 'wb');
            if ($readyPipe === false) {
                throw new RuntimeException('Could not open the ready barrier.');
            }
            fwrite($readyPipe, '1');
            fclose($readyPipe);

            $goPipe = fopen($go, 'rb');
            if ($goPipe === false || fread($goPipe, 1) !== '1') {
                throw new RuntimeException('Could not cross the release barrier.');
            }
            fclose($goPipe);
        });

        return Artisan::call('bfc:install:operator-credential');
    }
};

$_SERVER['BFC_INSTALL_DATABASE'] = $database;

try {
    exit($case->runProbe($phase, $ready, $go));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage());
    exit(1);
}
