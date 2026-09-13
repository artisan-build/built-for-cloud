<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DurableCredentialMinter;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

uses(RefreshDatabase::class);

function issueScopedClaimCode(Scope $scope, string $email): string
{
    $response = test()->postJson('/bfc/onboarding/issue', [
        'email' => $email,
        'scope' => $scope->value,
        'ttl_seconds' => 3600,
    ], ['Authorization' => 'Bearer '.auditOperatorCredential('scope-'.$scope->value.'-'.bin2hex(random_bytes(4)))])
        ->assertCreated();

    return (string) $response->json('claim_code');
}

it('always resolves the unified minter independently of the declaration', function (): void {
    app()->instance(CredentialDeclaration::class, new class implements CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }
    });

    expect(app(DurableCredentialMinter::class))->toBeInstanceOf(UnifiedStoreCredentialMinter::class);

    $code = auditIssueCode('declaration@example.test');

    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect(Credential::query()->where('subject_ref', 'declaration@example.test')->count())->toBe(1);
});

it('mints and verifies every accepted scope as an exactly linked unified bearer', function (Scope $scope): void {
    $email = $scope->value.'@example.test';
    $claimCode = issueScopedClaimCode($scope, $email);

    $response = $this->postJson('/bfc/onboarding/exchange', ['token' => $claimCode])
        ->assertCreated()
        ->assertJsonPath('name', $email);
    $secret = (string) $response->json('durable_token');
    $credential = Credential::query()->where('subject_ref', $email)->sole();
    $code = OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($claimCode))->sole();

    expect($credential->kind)->toBe(CredentialKind::Bearer)
        ->and($credential->subject_type)->toBe(SubjectType::ExternalConsumer)
        ->and($credential->subject_ref)->toBe($email)
        ->and($credential->abilities)->toBe([$scope->value])
        ->and($credential->secret_hash)->toBe(hash('sha256', $secret))
        ->and($code->durable_credential_id)->toBe($credential->id)
        ->and($code->consumed_at)->toBeNull();

    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$secret])
        ->assertOk()
        ->assertExactJson([
            'ok' => true,
            'name' => $email,
            'scope' => $scope->value,
        ]);

    expect($credential->refresh()->last_used_at)->not->toBeNull()
        ->and($code->refresh()->consumed_at)->not->toBeNull()
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $credential->id)
            ->where('event', LifecycleEventType::FirstUsed->value)
            ->exists())->toBeTrue();
})->with([
    'consume' => [Scope::Consume],
    'admin' => [Scope::Admin],
    'onboard' => [Scope::Onboard],
]);

it('refuses a malformed persisted scope before burning or minting', function (): void {
    $plain = 'malformed-claim-code';
    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'malformed@example.test',
        'scope' => 'unknown-persisted-scope',
        'token_hash' => OnboardingToken::hashToken($plain),
        'expires_at' => now()->addHour(),
    ]);
    $before = $code->only([
        'scope',
        'durable_credential_id',
        'consumed_at',
    ]);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $plain])
        ->assertBadRequest()
        ->assertJsonPath('error', 'invalid_code');

    expect($code->refresh()->only(array_keys($before)))->toBe($before)
        ->and(Credential::query()->count())->toBe(0);
});

it('re-exchanges make-before-break through the unified link', function (): void {
    $code = auditIssueCode('reclaim@example.test');
    $first = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');
    $second = (string) $this->postJson('/bfc/onboarding/exchange', ['token' => $code])
        ->assertCreated()->json('durable_token');

    $firstRow = Credential::query()->where('secret_hash', hash('sha256', $first))->sole();
    $secondRow = Credential::query()->where('secret_hash', hash('sha256', $second))->sole();

    expect($second)->not->toBe($first)
        ->and($firstRow->revoked_at)->not->toBeNull()
        ->and($secondRow->revoked_at)->toBeNull()
        ->and(OnboardingToken::query()->where('token_hash', OnboardingToken::hashToken($code))->sole()->durable_credential_id)->toBe($secondRow->id);

    $this->postJson('/bfc/onboarding/verify', [], ['Authorization' => 'Bearer '.$first])
        ->assertNotFound()
        ->assertJsonPath('error', 'code_not_found');
});

it('replaces an already revoked linked credential with a live credential', function (): void {
    $plain = bin2hex(random_bytes(32));
    $previous = Credential::factory()->revoked()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'relink@example.test',
        'name' => 'relink@example.test',
        'abilities' => [Scope::Consume->value],
    ]);
    $code = OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'relink@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => OnboardingToken::hashToken($plain),
        'durable_credential_id' => $previous->id,
        'expires_at' => now()->addHour(),
    ]);

    $this->postJson('/bfc/onboarding/exchange', ['token' => $plain])->assertCreated();

    expect($previous->refresh()->revoked_at)->not->toBeNull()
        ->and($code->refresh()->durable_credential_id)->not->toBe($previous->id)
        ->and(Credential::query()->whereKey($code->durable_credential_id)->exists())->toBeTrue();
});

it('sweeps the live same-subject credential while sparing one governed by another pending code', function (): void {
    $standing = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sweep@example.test',
        'abilities' => [Scope::Consume->value],
    ]);
    $governed = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'sweep@example.test',
        'abilities' => [Scope::Consume->value],
    ]);
    OnboardingToken::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'other@example.test',
        'scope' => Scope::Consume->value,
        'token_hash' => hash('sha256', 'other-code'),
        'durable_credential_id' => $governed->id,
        'expires_at' => now()->addHour(),
    ]);

    $code = auditIssueCode('sweep@example.test');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect($standing->refresh()->revoked_at)->not->toBeNull()
        ->and($governed->refresh()->revoked_at)->toBeNull();
});

it('spares a unified row in rotation grace from the exchange sweep', function (): void {
    $graced = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'rotated@example.test',
        'abilities' => [Scope::Consume->value],
        'rotated_at' => now(),
        'expires_at' => now()->addHour(),
    ]);
    $unmarked = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'rotated@example.test',
        'abilities' => [Scope::Consume->value],
    ]);

    $code = auditIssueCode('rotated@example.test');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect($graced->refresh()->revoked_at)->toBeNull()
        ->and($unmarked->refresh()->revoked_at)->not->toBeNull();
});

it('sweeps malformed rotation-grace shapes', function (): void {
    $unbounded = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'stamped@example.test',
        'abilities' => [Scope::Consume->value],
        'rotated_at' => now(),
        'expires_at' => null,
    ]);
    $overlong = Credential::factory()->create([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'stamped@example.test',
        'abilities' => [Scope::Consume->value],
        'rotated_at' => now(),
        'expires_at' => now()->addDays(30),
    ]);

    $code = auditIssueCode('stamped@example.test');
    $this->postJson('/bfc/onboarding/exchange', ['token' => $code])->assertCreated();

    expect($unbounded->refresh()->revoked_at)->not->toBeNull()
        ->and($overlong->refresh()->revoked_at)->not->toBeNull();
});

it('persists exchange and verification across fresh processes for every accepted scope and refuses malformed persisted scope', function (): void {
    foreach ([...Scope::cases(), 'malformed-persisted-scope'] as $scope) {
        $scopeValue = $scope instanceof Scope ? $scope->value : $scope;
        $database = tempnam(sys_get_temp_dir(), 'bfc-p5b-claim-');
        expect($database)->toBeString();

        try {
            $setup = runUnifiedClaimProcess('setup', $database, $scopeValue);
            $claimCode = $setup['claim_code'];
            $exchange = runUnifiedClaimProcess('exchange', $database, $claimCode);
            $inspection = runUnifiedClaimProcess('inspect', $database, $claimCode);

            if (! $scope instanceof Scope) {
                expect($exchange['status'])->toBe(400)
                    ->and($exchange['body']['error'])->toBe('invalid_code')
                    ->and($inspection['scope'])->toBe($scopeValue)
                    ->and($inspection['consumed'])->toBeFalse()
                    ->and($inspection['durable_credential_id'])->toBeNull()
                    ->and($inspection['credentials'])->toBe(0);

                continue;
            }

            $secret = $exchange['body']['durable_token'];
            $credential = $inspection['credential'];

            expect($exchange['status'])->toBe(201)
                ->and($inspection['durable_credential_id'])->toBe($credential['id'])
                ->and($inspection['credentials'])->toBe(1)
                ->and($credential['kind'])->toBe(CredentialKind::Bearer->value)
                ->and($credential['subject_type'])->toBe(SubjectType::ExternalConsumer->value)
                ->and($credential['subject_ref'])->toBe($scopeValue.'@fresh-process.test')
                ->and($credential['abilities'])->toBe([$scopeValue])
                ->and($credential['secret_hash'])->toBe(hash('sha256', $secret));

            $verified = runUnifiedClaimProcess('verify', $database, $secret);
            expect($verified['status'])->toBe(200)
                ->and($verified['body']['scope'])->toBe($scopeValue);
        } finally {
            if (is_string($database) && is_file($database)) {
                unlink($database);
            }
        }
    }
});

/** @return array<string, mixed> */
function runUnifiedClaimProcess(string $phase, string $database, string $value): array
{
    $process = new Process([
        PHP_BINARY,
        __DIR__.'/Fixtures/unified-claim-process.php',
        $phase,
        $database,
        $value,
    ]);
    $process->run();

    expect($process->isSuccessful())->toBeTrue($process->getOutput().$process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}
