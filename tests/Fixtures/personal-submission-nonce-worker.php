<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiPersonalCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid personal submission nonce worker input.\n");
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
        // The parent PostgreSQL lane owns the migrated schema shared by both workers.
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('database.default', 'pgsql_testing');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('queue.default', 'sync');
        $app['config']->set('built-for-cloud.credentials.declaration', UiPersonalCredentialDeclaration::class);
        $app['config']->set('built-for-cloud.credentials.app_purposes', [
            'test.consume' => CredentialPurpose::Consumption->value,
        ]);
        $app['config']->set('built-for-cloud.ui.credential_purposes', ['test.consume']);
        $app['config']->set('built-for-cloud.ui.personal_credentials', true);
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array{status: int, has_delivery: bool}
     */
    public function runProbe(array $input): array
    {
        parent::setUp();

        UiPersonalCredentialDeclaration::$kinds = [CredentialKind::Bearer];
        UiPersonalCredentialDeclaration::$abilities = [OperatorAbility::McpRead->value];
        UiPersonalCredentialDeclaration::$deniedVerbs = [];
        UiPersonalCredentialDeclaration::$resolvesSubject = true;
        UiPersonalCredentialDeclaration::$subjectRef = null;
        DB::connection()->statement(
            "set application_name = 'bfc-p5-ui-d-nonce-worker-".(int) $input['worker']."'",
        );
        $user = User::query()->findOrFail($input['user_id']);
        $response = $this->actingAsVersioned($user, 'web')
            ->withSession(['_token' => $input['session_token']])
            ->post('/bfc/ui/credentials/personal', [
                SubmissionNonce::FIELD => $input['submission_nonce'],
                'app_purpose' => 'test.consume',
                'kind' => CredentialKind::Bearer->value,
                'name' => 'concurrent-personal-credential',
            ]);

        return [
            'status' => $response->getStatusCode(),
            'has_delivery' => str_contains(
                (string) $response->getContent(),
                'data-testid="personal-credentials-delivery"',
            ),
        ];
    }
};

try {
    $result = $case->runProbe($input);
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR));
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage()."\n".$exception->getTraceAsString());
    exit(1);
}
