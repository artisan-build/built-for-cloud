<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\InstallHmacCredentialFromClaim;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\HmacCredentialTransfer;
use ArtisanBuild\BuiltForCloud\ImportedHmacSecret;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\SensitiveString;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input)) {
    fwrite(STDERR, "Invalid HMAC install worker input.\n");
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
        $app['config']->set('built-for-cloud.credentials.app_purposes', ['matte.callback' => CredentialPurpose::Signing->value]);
        $app['config']->set('built-for-cloud.ui.credential_purposes', ['matte.callback']);
    }

    /** @param array<string, mixed> $input @return array<string, mixed> */
    public function runProbe(array $input): array
    {
        parent::setUp();
        DB::statement("set application_name = 'bfc-hmac-install-worker-".(int) $input['worker']."'");
        DB::statement("set lock_timeout = '10s'");
        $scope = new BoundCredentialScope(
            (string) $input['app_purpose'],
            new Subject(SubjectType::from((string) $input['subject_type']), (string) $input['subject_ref']),
            (string) $input['installation'],
            (string) $input['application'],
            (string) $input['audience'],
        );
        $claimed = ClaimedHmacCredential::fromIssuerResponse(
            HmacCredentialTransfer::fromIssuerResponse(
                (string) $input['replacement_id'],
                $scope,
                'hmac-sha256',
                CarbonImmutable::parse((string) $input['credential_expires_at']),
                (int) $input['generation'],
                (string) $input['fingerprint'],
                (string) $input['predecessor_id'],
                CredentialStatus::Pending,
                CarbonImmutable::parse((string) $input['delivered_at']),
                CarbonImmutable::parse((string) $input['transfer_expires_at']),
            ),
            ImportedHmacSecret::fromIssuerResponse((string) $input['key']),
        );
        $issuer = new class($claimed) implements HmacCredentialIssuerClient
        {
            public function __construct(private readonly ClaimedHmacCredential $claimed) {}

            public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential
            {
                $claimCode->reveal();

                return $this->claimed;
            }

            public function activate(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId, string $deliveryFingerprint): IssuerHmacCutoverReceipt
            {
                throw new LogicException('Not used.');
            }

            public function cutoverStatus(BoundCredentialScope $expectedScope, ?string $predecessorId, string $replacementId): IssuerHmacCutoverReceipt
            {
                throw new LogicException('Not used.');
            }
        };

        try {
            $result = app(InstallHmacCredentialFromClaim::class)($scope, $issuer, str_repeat('c', 64));

            return ['outcome' => 'installed', 'credential_id' => $result->credentialId];
        } catch (HmacCredentialTransferRefused $refused) {
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
