<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

abstract class PurposeMigrationTestCase extends TestCase
{
    protected const string PURPOSE_MIGRATION = '2026_09_14_000001_add_purpose_to_credentials_table.php';

    protected function assertFreshPurposeSchema(string $connectionName): void
    {
        $connection = DB::connection($connectionName);
        $this->assertPurposeColumn($connection);

        $mint = app(MintCredential::class)(
            new Subject(SubjectType::ExternalConsumer, 'fresh-purpose-'.bin2hex(random_bytes(5))),
            new MintOptions(purpose: CredentialPurpose::Consumption),
        );
        $rotation = app(RotateCredential::class)($mint->summary->id, new RotateOptions);

        $this->assertSame(CredentialPurpose::Consumption, $mint->summary->purpose);
        $this->assertSame(CredentialPurpose::Consumption, $rotation?->mint->summary->purpose);
        $this->assertSame(0, Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]));
        $listed = collect(json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR))
            ->firstWhere('id', $rotation?->mint->summary->id);
        $this->assertSame(CredentialPurpose::Consumption->value, $listed['purpose']);
    }

    protected function assertUpgradeAndRollback(string $connectionName): void
    {
        $connection = DB::connection($connectionName);
        $this->migratePrePurpose($connectionName);
        $fixture = $this->insertLegacyRows($connection);
        $before = $connection->table('credentials')->orderBy('id')->get([
            'id', 'status', 'subject_type', 'subject_ref', 'abilities', 'revoked_at',
        ])->map(static fn (object $row): array => (array) $row)->all();

        $this->runPurposeMigration($connectionName);
        $this->assertPurposeColumn($connection);

        $rows = $connection->table('credentials')->orderBy('id')->get();
        $after = $rows->map(static fn (object $row): array => (array) $row)->all();
        $preserved = $rows->map(static fn (object $row): array => [
            'id' => $row->id,
            'status' => $row->status,
            'subject_type' => $row->subject_type,
            'subject_ref' => $row->subject_ref,
            'abilities' => $row->abilities,
            'revoked_at' => $row->id === $fixture['already_revoked_id'] ? $row->revoked_at : null,
        ])->all();
        $expected = array_map(static function (array $row) use ($fixture): array {
            if ($row['id'] !== $fixture['already_revoked_id']) {
                $row['revoked_at'] = null;
            }

            return $row;
        }, $before);

        $this->assertCount(5, $after);
        $this->assertSame(array_column($before, 'id'), array_column($after, 'id'));
        $this->assertSame($expected, $preserved);
        $this->assertSame(
            (string) collect($before)->firstWhere('id', $fixture['already_revoked_id'])['revoked_at'],
            (string) collect($after)->firstWhere('id', $fixture['already_revoked_id'])['revoked_at'],
        );
        $this->assertSame([null], array_values(array_unique(array_column($after, 'purpose'))));

        $newlyRetired = collect($after)
            ->where('id', '!=', $fixture['already_revoked_id'])
            ->pluck('revoked_at')
            ->all();
        $this->assertCount(1, array_unique($newlyRetired));
        $this->assertNotNull($newlyRetired[0]);

        $this->assertSame(0, Artisan::call('bfc:credential:list', ['--local' => true]));
        $table = Artisan::output();
        $this->assertSame(0, Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]));
        $json = Artisan::output();
        $listed = collect(json_decode($json, true, flags: JSON_THROW_ON_ERROR))->keyBy('id');

        foreach ($fixture['ids'] as $id) {
            $this->assertStringContainsString($id, $table);
            $this->assertSame('revoked', $listed[$id]['status']);
            $this->assertNull($listed[$id]['purpose']);
        }

        foreach ($fixture['secret_material'] as $material) {
            $this->assertStringNotContainsString($material, $table);
            $this->assertStringNotContainsString($material, $json);
        }

        $this->assertLegacyCredentialsRefuse($fixture);

        $this->assertSame(0, Artisan::call('migrate:rollback', [
            '--database' => $connectionName,
            '--step' => 1,
            '--force' => true,
        ]));
        $this->assertFalse(Schema::connection($connectionName)->hasColumn('credentials', 'purpose'));
        $this->assertSame(5, $connection->table('credentials')->whereNotNull('revoked_at')->count());
        $this->assertLegacyCredentialsRefuse($fixture);
    }

    /**
     * @return array{
     *   ids: list<string>, already_revoked_id: string, already_revoked_at: string,
     *   bearer_secret: string, basic_secret: string, hmac_subject: Subject,
     *   hmac_header: string, hmac_body: string, asymmetric_subject: Subject,
     *   secret_material: list<string>
     * }
     */
    private function insertLegacyRows(Connection $connection): array
    {
        $bearerSecret = 'legacy-bearer-'.bin2hex(random_bytes(8));
        $basicSecret = 'legacy-basic-'.bin2hex(random_bytes(8));
        $hmacSecret = 'legacy-hmac-'.bin2hex(random_bytes(8));
        $hmacSubject = new Subject(SubjectType::ExternalConsumer, 'legacy-hmac-subject');
        $asymmetricSubject = new Subject(SubjectType::Installation, 'legacy-asymmetric-subject');
        $encrypted = app(HmacKeyring::class)->encrypt($hmacSecret);
        $publicKey = CredentialFactory::generatePublicKey();
        $alreadyRevokedAt = '2026-09-13 04:05:06';
        $createdAt = '2026-09-12 01:02:03';
        $ids = [
            '10000000-0000-4000-8000-000000000001',
            '10000000-0000-4000-8000-000000000002',
            '10000000-0000-4000-8000-000000000003',
            '10000000-0000-4000-8000-000000000004',
            '10000000-0000-4000-8000-000000000005',
        ];

        $legacyRows = [
            [
                'id' => $ids[0], 'kind' => CredentialKind::Bearer->value,
                'subject_type' => SubjectType::Application->value, 'subject_ref' => 'legacy-bearer-subject',
                'name' => 'legacy bearer', 'abilities' => json_encode(['legacy:unknown'], JSON_THROW_ON_ERROR),
                'secret_hash' => hash('sha256', $bearerSecret), 'status' => 'active',
                'created_at' => $createdAt, 'updated_at' => $createdAt,
            ],
            [
                'id' => $ids[1], 'kind' => CredentialKind::Basic->value,
                'subject_type' => SubjectType::Operator->value, 'subject_ref' => 'legacy-basic-subject',
                'name' => 'legacy basic', 'abilities' => json_encode([OperatorAbility::CredentialRead->value], JSON_THROW_ON_ERROR),
                'secret_hash' => hash('sha256', $basicSecret), 'status' => 'pending',
                'created_at' => $createdAt, 'updated_at' => $createdAt,
            ],
            [
                'id' => $ids[2], 'kind' => CredentialKind::Hmac->value,
                'subject_type' => $hmacSubject->type->value, 'subject_ref' => $hmacSubject->ref,
                'name' => 'legacy hmac', 'abilities' => null, 'status' => 'active',
                'secret_ciphertext' => $encrypted->ciphertext, 'secret_key_version' => $encrypted->keyVersion,
                'delivery_fingerprint' => 'legacy-delivery-fingerprint',
                'created_at' => $createdAt, 'updated_at' => $createdAt,
            ],
            [
                'id' => $ids[3], 'kind' => CredentialKind::Asymmetric->value,
                'subject_type' => $asymmetricSubject->type->value, 'subject_ref' => $asymmetricSubject->ref,
                'name' => 'legacy asymmetric', 'abilities' => json_encode([], JSON_THROW_ON_ERROR),
                'public_key' => $publicKey, 'status' => 'active',
                'created_at' => $createdAt, 'updated_at' => $createdAt,
            ],
            [
                'id' => $ids[4], 'kind' => CredentialKind::Bearer->value,
                'subject_type' => SubjectType::UserPrincipal->value, 'subject_ref' => 'legacy-already-revoked',
                'name' => 'legacy revoked', 'abilities' => null,
                'secret_hash' => hash('sha256', 'legacy-already-revoked-secret'),
                'status' => 'active', 'revoked_at' => $alreadyRevokedAt,
                'created_at' => $createdAt, 'updated_at' => $createdAt,
            ],
        ];

        foreach ($legacyRows as $legacyRow) {
            $connection->table('credentials')->insert($legacyRow);
        }

        $body = '{"migration":"retirement"}';
        $envelope = new HmacEnvelope(
            keyId: $ids[2],
            eventType: 'migration.test',
            timestamp: now()->getTimestamp(),
            nonce: bin2hex(random_bytes(12)),
            audience: (string) config('built-for-cloud.hmac.audience'),
        );
        $header = $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $hmacSecret));

        return [
            'ids' => $ids,
            'already_revoked_id' => $ids[4],
            'already_revoked_at' => $alreadyRevokedAt,
            'bearer_secret' => $bearerSecret,
            'basic_secret' => $basicSecret,
            'hmac_subject' => $hmacSubject,
            'hmac_header' => $header,
            'hmac_body' => $body,
            'asymmetric_subject' => $asymmetricSubject,
            'secret_material' => [
                hash('sha256', $bearerSecret), hash('sha256', $basicSecret),
                hash('sha256', 'legacy-already-revoked-secret'),
                $encrypted->ciphertext, $encrypted->keyVersion,
                'legacy-delivery-fingerprint', $publicKey, $header,
            ],
        ];
    }

    /** @param array<string, mixed> $fixture */
    private function assertLegacyCredentialsRefuse(array $fixture): void
    {
        $resolver = app(CredentialResolver::class);
        $this->assertNull($resolver->resolve(CredentialKind::Bearer, $fixture['bearer_secret']));
        $this->assertNull($resolver->resolve(CredentialKind::Basic, $fixture['basic_secret']));
        try {
            app(HmacSigner::class)->sign($fixture['hmac_subject'], $fixture['hmac_body'], 'migration.test');
            $this->fail('The retired legacy HMAC key unexpectedly signed.');
        } catch (HmacSigningRefused) {
            $this->addToAssertionCount(1);
        }

        $this->assertHmacVerificationRefuses($fixture);
        $this->assertSame([], Credential::activePublicKeysFor(
            $fixture['asymmetric_subject']->type,
            $fixture['asymmetric_subject']->ref,
        ));
    }

    /** @param array<string, mixed> $fixture */
    private function assertHmacVerificationRefuses(array $fixture): void
    {
        try {
            app(HmacVerifier::class)->verify(
                $fixture['hmac_subject'],
                $fixture['hmac_header'],
                $fixture['hmac_body'],
            );
            $this->fail('The retired legacy HMAC key unexpectedly verified.');
        } catch (HmacVerificationFailed) {
            $this->addToAssertionCount(1);
        }
    }

    private function migratePrePurpose(string $connectionName): void
    {
        $paths = glob(__DIR__.'/../../database/migrations/*.php');
        $this->assertIsArray($paths);
        $paths = array_values(array_filter(
            $paths,
            static fn (string $path): bool => basename($path) !== self::PURPOSE_MIGRATION,
        ));

        $this->assertSame(0, Artisan::call('migrate:fresh', [
            '--database' => $connectionName,
            '--path' => $paths,
            '--realpath' => true,
            '--force' => true,
        ]), Artisan::output());
        $this->assertFalse(Schema::connection($connectionName)->hasColumn('credentials', 'purpose'));
    }

    private function runPurposeMigration(string $connectionName): void
    {
        $this->assertSame(0, Artisan::call('migrate', [
            '--database' => $connectionName,
            '--path' => [__DIR__.'/../../database/migrations/'.self::PURPOSE_MIGRATION],
            '--realpath' => true,
            '--force' => true,
        ]), Artisan::output());
    }

    private function assertPurposeColumn(Connection $connection): void
    {
        if ($connection->getDriverName() === 'pgsql') {
            $column = $connection->table('information_schema.columns')
                ->where('table_schema', 'public')
                ->where('table_name', 'credentials')
                ->where('column_name', 'purpose')
                ->first();

            $this->assertNotNull($column);
            $this->assertSame('character varying', $column->data_type);
            $this->assertSame('YES', $column->is_nullable);
            $this->assertNull($column->column_default);

            return;
        }

        $column = collect($connection->select("PRAGMA table_info('credentials')"))
            ->first(static fn (object $column): bool => $column->name === 'purpose');

        $this->assertNotNull($column);
        $this->assertSame('varchar', strtolower((string) $column->type));
        $this->assertSame(0, $column->notnull);
        $this->assertNull($column->dflt_value);
    }
}
