<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnifiedStoreDeclaration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * @return array<string, array{CredentialKind, DeliveryShape, CredentialStatus, string, array<string, mixed>}>
 */
function directCredentialDeliveryTable(): array
{
    return [
        'bearer direct' => [CredentialKind::Bearer, DeliveryShape::Bearer, CredentialStatus::Active, 'hash', []],
        'basic direct' => [CredentialKind::Basic, DeliveryShape::BasicAuth, CredentialStatus::Active, 'hash', []],
        'asymmetric enrollment code' => [CredentialKind::Asymmetric, DeliveryShape::EnrollmentCode, CredentialStatus::Pending, 'keyless-code', ['code_ttl_seconds' => 900]],
        'hmac direct' => [CredentialKind::Hmac, DeliveryShape::SigningKey, CredentialStatus::Pending, 'ciphertext', []],
        'hmac claim code' => [CredentialKind::Hmac, DeliveryShape::SigningKeyCode, CredentialStatus::Pending, 'ciphertext-code', ['code_ttl_seconds' => 900]],
    ];
}

/**
 * P5-AC6's direct-delivery table. It proves the shared action boundary and
 * persisted rows for every current kind/delivery variant, including the
 * absence of server-held asymmetric key material. It cannot prove a future
 * asymmetric registration/verifier, transport code outside the shared
 * MintResult boundary, or deliberate direct-model/keyring reads. Existing
 * HTTP/CLI parity and MintedSecret tests cover those supported renderers and
 * the sealed carrier; R1 owns asymmetric completion.
 *
 * @param  array<string, mixed>  $input
 */
it('holds the per-kind direct delivery boundary', function (
    CredentialKind $kind,
    DeliveryShape $delivery,
    CredentialStatus $status,
    string $storage,
    array $input,
): void {
    $subject = new Subject(SubjectType::ExternalConsumer, 'matrix-'.$kind->value.'-'.$delivery->value);
    $revealed = null;

    /** @var MintResult $result */
    $result = $this->assertNoSecretLeakageOfMinted(
        fn (): MintResult => app(MintCredential::class)(
            $subject,
            MintOptions::fromInput(['kind' => $kind->value, ...$input]),
        ),
        function (MintResult $mint) use (&$revealed): string {
            expect($mint->secret)->not->toBeNull();
            $revealed = $mint->secret?->reveal();

            return $revealed ?? '';
        },
    );

    $credential = Credential::query()->findOrFail($result->summary->id);

    expect($result->delivery)->toBe($delivery)
        ->and($credential->kind)->toBe($kind)
        ->and($credential->status)->toBe($status)
        ->and($revealed)->toBeString()->not->toBe('')
        ->and(fn () => $result->secret?->reveal())->toThrow(LogicException::class);

    if ($storage === 'hash') {
        expect($credential->secret_hash)->toBe(hash('sha256', (string) $revealed))
            ->and($credential->secret_ciphertext)->toBeNull()
            ->and($credential->public_key)->toBeNull();

        return;
    }

    if ($storage === 'keyless-code') {
        $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->sole();

        expect($credential->secret_hash)->toBeNull()
            ->and($credential->secret_ciphertext)->toBeNull()
            ->and($credential->public_key)->toBeNull()
            ->and($code->token_hash)->toBe(hash('sha256', (string) $revealed));

        return;
    }

    $storedKey = app(HmacKeyring::class)->decrypt(
        (string) $credential->secret_ciphertext,
        $credential->secret_key_version,
    );

    expect($credential->secret_hash)->toBeNull()
        ->and($credential->public_key)->toBeNull();

    if ($storage === 'ciphertext') {
        expect($storedKey)->toBe($revealed)
            ->and($credential->delivered_at)->not->toBeNull();

        return;
    }

    $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->sole();

    expect($storedKey)->not->toBe($revealed)
        ->and($code->token_hash)->toBe(hash('sha256', (string) $revealed))
        ->and($credential->delivered_at)->toBeNull();
})->with(directCredentialDeliveryTable());

it('enumerates every credential kind in the delivery table without inventing a signing root', function (): void {
    $kinds = array_map(
        static fn (array $row): string => $row[0]->value,
        directCredentialDeliveryTable(),
    );
    $kinds = array_values(array_unique($kinds));
    sort($kinds);

    $expected = CredentialKind::values();
    sort($expected);

    expect($kinds)->toBe($expected);
});

/**
 * P5-AC6's installation-locality control. The separate in-memory connection
 * represents another installation store; this does not claim hostile-host
 * resistance or any caller-selected cross-installation routing path.
 */
it('resolves a stored secret only in the installation store that contains its hash', function (): void {
    $secret = 'installation-local-secret';
    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'installation-a',
        'user_id' => null,
        'secret_hash' => hash('sha256', $secret),
    ]);
    $hmacSubject = new Subject(SubjectType::Installation, 'installation-a');
    Credential::factory()->hmac()->activated()->create([
        'subject_type' => $hmacSubject->type,
        'subject_ref' => $hmacSubject->ref,
    ]);
    $hmacBody = '{}';
    $hmacHeader = app(HmacSigner::class)->sign($hmacSubject, $hmacBody, 'locality.control');

    config()->set('database.connections.separate_installation', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    DB::purge('separate_installation');

    Schema::connection('separate_installation')->create('credentials', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->string('kind', 32);
        $table->string('subject_type', 32);
        $table->string('subject_ref');
        $table->string('user_id')->nullable();
        $table->string('secret_hash', 64)->nullable()->unique();
        $table->text('secret_ciphertext')->nullable();
        $table->string('status', 16);
        $table->timestamp('revoked_at')->nullable();
        $table->timestamp('expires_at')->nullable();
    });
    Schema::connection('separate_installation')->create('offboarded_subjects', function (Blueprint $table): void {
        $table->string('subject_type');
        $table->string('subject_ref');
        $table->string('user_id')->default('');
    });

    expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret)?->id)->toBe($credential->id);

    $originalConnection = DB::getDefaultConnection();

    try {
        DB::setDefaultConnection('separate_installation');

        expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret))->toBeNull();
        expect(fn () => app(HmacVerifier::class)->verify($hmacSubject, $hmacHeader, $hmacBody))
            ->toThrow(HmacVerificationFailed::class, 'No usable signing key matches');

        DB::connection()->table('credentials')->insert([
            'id' => $credential->id,
            'kind' => $credential->kind->value,
            'subject_type' => $credential->subject_type->value,
            'subject_ref' => $credential->subject_ref,
            'user_id' => null,
            'secret_hash' => $credential->secret_hash,
            'status' => $credential->status->value,
            'revoked_at' => null,
            'expires_at' => null,
        ]);

        expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret)?->id)->toBe($credential->id);
    } finally {
        DB::setDefaultConnection($originalConnection);
        DB::purge('separate_installation');
    }
});

/**
 * P5-AC6's exchange-minted bearer rows, driven through both public response
 * faces. This proves the code and bearer are distinct secrets, only the hash
 * reaches the selected unified store, and credential listing is not a
 * read-back path. It does not claim every declaration already selects this
 * store: the legacy default intentionally remains transitional until P5c.
 */
it('delivers a distinct exchange-minted bearer once on both response faces', function (string $face): void {
    app()->bind(CredentialDeclaration::class, UnifiedStoreDeclaration::class);
    $claimCode = auditIssueCode('matrix-'.$face.'@example.test');

    /** @var TestResponse<Response> $response */
    $response = $face === 'token'
        ? $this->postJson('/bfc/claim', ['version' => 1, 'claim_code' => $claimCode])->assertOk()
        : $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    $bearer = (string) $response->json($face);
    $credential = Credential::query()->where('secret_hash', hash('sha256', $bearer))->sole();

    expect($bearer)->not->toBe('')
        ->and($bearer)->not->toBe($claimCode)
        ->and($credential->kind)->toBe(CredentialKind::Bearer)
        ->and($credential->secret_hash)->toBe(hash('sha256', $bearer));

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $bearer);

    $listing = $this->getJson('/bfc/credentials', [
        'Authorization' => 'Bearer '.auditAdminToken('matrix-list-'.$face),
    ])->assertOk();

    $this->assertResponseCarriesNoSecret($listing, $bearer);
})->with(['token', 'durable_token']);

/**
 * P5-AC6's HMAC-by-code second boundary. It proves mint reveals only a code,
 * exchange reveals the pending key exactly once, and no third package
 * read-back exists. It does not claim activation or asymmetric enrollment;
 * those are separate lifecycle and R1-owned concerns.
 */
it('delivers an hmac key at exchange without activating or exposing it later', function (): void {
    $mint = app(MintCredential::class)(
        new Subject(SubjectType::ExternalConsumer, 'matrix-hmac-exchange'),
        MintOptions::fromInput(['kind' => 'hmac', 'code_ttl_seconds' => 900]),
    );
    $claimCode = $mint->secret?->reveal();
    expect($claimCode)->toBeString()->not->toBe('');

    /** @var TestResponse<Response> $response */
    $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])->assertCreated();
    $signingKey = (string) $response->json('signing_key');
    $credential = Credential::query()->findOrFail($mint->summary->id);

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $signingKey);

    expect($signingKey)->not->toBe($claimCode)
        ->and($credential->status)->toBe(CredentialStatus::Pending)
        ->and($credential->activated_at)->toBeNull()
        ->and(app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version))->toBe($signingKey);

    $listing = $this->getJson('/bfc/credentials', [
        'Authorization' => 'Bearer '.auditAdminToken('matrix-hmac-list'),
    ])->assertOk();

    $this->assertResponseCarriesNoSecret($listing, $signingKey);
});
