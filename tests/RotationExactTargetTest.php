<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\CompleteAsymmetricEnrollment;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOwnership;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\ExactCredentialTarget;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * THE CONSUMER-SHAPED SOURCE ROW.
 *
 * An ingest credential as a consumer pre-selects one: a bearer credential
 * for consumption, bound to one installation subject, installation-owned.
 * Those four dimensions are the predicate; everything the package already
 * rechecks (pending/revoked/expired/rotated) is left at its live default.
 */
function exactTargetSource(array $overrides = []): Credential
{
    return Credential::factory()->create(array_merge([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'app-a',
        'name' => 'ingest',
        'user_id' => null,
        'expires_at' => now()->addDays(30),
    ], $overrides));
}

function exactTargetFor(array $overrides = []): ExactCredentialTarget
{
    return new ExactCredentialTarget(
        purpose: $overrides['purpose'] ?? CredentialPurpose::Consumption,
        subject: $overrides['subject'] ?? new Subject(SubjectType::Installation, 'app-a'),
        kind: $overrides['kind'] ?? CredentialKind::Bearer,
        ownership: $overrides['ownership'] ?? CredentialOwnership::Installation,
    );
}

/**
 * A retarget written straight through the query builder — deliberately
 * NOT through the model, because the point of the predicate is that the
 * package cannot assume who moved the row or how.
 */
function exactTargetRetarget(string $id, array $attributes): void
{
    DB::table('credentials')->where('id', $id)->update($attributes);
}

/** @return array{credentials: int, audits: int} */
function exactTargetTotals(): array
{
    return [
        'credentials' => Credential::query()->count(),
        'audits' => CredentialAuditEvent::query()->count(),
    ];
}

it('rotates exactly as today when the locked row still matches the exact target', function (): void {
    $source = exactTargetSource();

    $result = app(RotateCredential::class)($source->id, new RotateOptions(target: exactTargetFor()));
    $replacement = Credential::query()->findOrFail($result?->mint->summary->id);

    expect($result)->not->toBeNull()
        ->and($replacement->purpose)->toBe(CredentialPurpose::Consumption)
        ->and($replacement->subject_type)->toBe(SubjectType::Installation)
        ->and($replacement->subject_ref)->toBe('app-a')
        ->and($replacement->kind)->toBe(CredentialKind::Bearer)
        ->and($replacement->user_id)->toBeNull()
        ->and($replacement->name)->toBe('ingest')
        ->and($result?->mint->secret?->reveal())->toBeString()
        ->and(Credential::query()->findOrFail($source->id)->rotated_at)->not->toBeNull();
});

it('refuses a rotation whose locked row was retargeted to another subject, with no side effects', function (): void {
    $source = exactTargetSource();
    $target = exactTargetFor();
    exactTargetRetarget($source->id, ['subject_ref' => 'app-b']);
    $before = exactTargetTotals();

    expect(fn () => app(RotateCredential::class)($source->id, new RotateOptions(target: $target)))
        ->toThrow(RotationRefused::class, 'subject');

    expect(exactTargetTotals())->toBe($before)
        ->and(Credential::query()->findOrFail($source->id)->rotated_at)->toBeNull()
        ->and(Credential::query()->findOrFail($source->id)->expires_at?->toDateTimeString())
        ->toBe($source->expires_at?->toDateTimeString());
})->note('AC1. The refusal is the whole phase-one transaction rolling back: nothing minted, nothing stamped, nothing retired.');

it('refuses each pinned dimension the locked row no longer carries', function (array $retarget, string $dimension): void {
    $source = exactTargetSource();
    $target = exactTargetFor();
    exactTargetRetarget($source->id, $retarget);
    $before = exactTargetTotals();

    expect(fn () => app(RotateCredential::class)($source->id, new RotateOptions(target: $target)))
        ->toThrow(RotationRefused::class, $dimension);

    expect(exactTargetTotals())->toBe($before)
        ->and(Credential::query()->findOrFail($source->id)->rotated_at)->toBeNull();
})->with([
    'purpose' => [['purpose' => CredentialPurpose::Mcp->value], 'purpose'],
    'subject type' => [['subject_type' => SubjectType::ExternalConsumer->value], 'subject'],
    'subject ref' => [['subject_ref' => 'app-b'], 'subject'],
    'kind' => [['kind' => CredentialKind::Basic->value], 'kind'],
    'ownership' => [['user_id' => '7'], 'ownership'],
    'purpose cleared' => [['purpose' => null], 'purpose'],
]);

it('pins only the dimensions the caller supplied', function (): void {
    // kind and ownership left out: the caller said it does not care, and
    // a row that differs on exactly those still rotates. The absent
    // dimension must not become a silent assertion.
    $source = exactTargetSource(['kind' => CredentialKind::Basic, 'user_id' => '7']);

    $result = app(RotateCredential::class)($source->id, new RotateOptions(
        target: new ExactCredentialTarget(
            purpose: CredentialPurpose::Consumption,
            subject: new Subject(SubjectType::Installation, 'app-a'),
        ),
    ));

    expect($result)->not->toBeNull()
        ->and(Credential::query()->findOrFail($source->id)->rotated_at)->not->toBeNull();
});

it('leaves a mismatched rotation submission nonce unconsumed', function (): void {
    // A refused rotation does not burn the operator's one permit. The
    // predicate is checked before the consume, but the consume is itself a
    // conditional DELETE inside the phase-one transaction, so the ROLLBACK
    // is what this test actually observes. Moving the check after the
    // consume leaves it green; the claim is the outcome, not the ordering.
    $source = exactTargetSource();
    $target = exactTargetFor();
    $nonce = SubmissionNonce::issue('session-exact-target', '42', CredentialVerb::Rotate, $source->id);
    $presented = SubmissionNonce::presented($nonce, 'session-exact-target', '42', CredentialVerb::Rotate, $source->id);
    exactTargetRetarget($source->id, ['subject_ref' => 'app-b']);

    expect(fn () => app(RotateCredential::class)(
        $source->id,
        new RotateOptions(target: $target),
        submission: $presented,
    ))->toThrow(RotationRefused::class);

    expect(DB::table('bfc_submission_nonces')->count())->toBe(1);
})->note('AC1 "without side effects": a refused rotation leaves the permit usable for a corrected call. Proven by the phase-one rollback, not by the check order. Debt row bfc-rotate-exact-target-nonce-order.');

it('refuses the cutover completion of a retargeted row', function (): void {
    // The stamped-row path reaches the same locked recheck, so completion
    // of a rotation whose source has since been retargeted refuses too.
    $source = exactTargetSource();
    $target = exactTargetFor();
    $first = app(RotateCredential::class)($source->id, new RotateOptions(target: $target));
    exactTargetRetarget($source->id, ['subject_ref' => 'app-b']);
    $before = exactTargetTotals();

    expect(fn () => app(RotateCredential::class)($source->id, new RotateOptions(target: $target)))
        ->toThrow(RotationRefused::class, 'subject');

    expect(exactTargetTotals())->toBe($before)
        ->and($first?->mint->summary->id)->toBeString();
});

it('refuses a bound delivery reissue whose locked row was retargeted', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );
    app(CompleteAsymmetricEnrollment::class)(
        $mint->secret?->reveal() ?? '',
        $scope,
        new Rs256PublicKey(testsRsaKey()['public']),
    );
    app(RotateCredential::class)($mint->summary->id, new RotateOptions(codeTtlSeconds: 3600));
    $target = new ExactCredentialTarget(
        purpose: CredentialPurpose::Signing,
        subject: $scope->subject,
        kind: CredentialKind::Asymmetric,
    );
    exactTargetRetarget($mint->summary->id, ['subject_ref' => 'moved-installation']);
    $before = [
        ...exactTargetTotals(),
        'codes' => OnboardingToken::query()->count(),
        'consumed' => OnboardingToken::query()->whereNotNull('consumed_at')->count(),
    ];

    expect(fn () => app(RotateCredential::class)(
        $mint->summary->id,
        new RotateOptions(codeTtlSeconds: 3600, reissuePendingDelivery: true, target: $target),
    ))->toThrow(RotationRefused::class, 'subject');

    expect([
        ...exactTargetTotals(),
        'codes' => OnboardingToken::query()->count(),
        'consumed' => OnboardingToken::query()->whereNotNull('consumed_at')->count(),
    ])->toBe($before);
})->note('The reissue entry point holds its own lock on the source row, so the predicate is enforced there as well as on the minting path.');

it('refuses a signing-root rotation whose exact target names something else', function (): void {
    app(SigningRootLifecycle::class)->ensure();
    $root = Credential::query()
        ->where('purpose', CredentialPurpose::SigningRoot)
        ->whereNull('rotated_at')
        ->sole();
    $before = exactTargetTotals();

    expect(fn () => app(RotateCredential::class)($root->id, new RotateOptions(target: exactTargetFor())))
        ->toThrow(RotationRefused::class, 'purpose');

    expect(exactTargetTotals())->toBe($before)
        ->and(Credential::query()->findOrFail($root->id)->rotated_at)->toBeNull();
});

it('asserts nothing for a caller that supplies no exact target', function (): void {
    // Backward compatibility, stated as a test: the option is additive,
    // and every existing caller constructs RotateOptions without it.
    $source = exactTargetSource();
    $options = new RotateOptions;
    exactTargetRetarget($source->id, ['subject_ref' => 'app-b', 'purpose' => CredentialPurpose::Mcp->value]);

    $result = app(RotateCredential::class)($source->id, $options);

    expect($options->target)->toBeNull()
        ->and($result)->not->toBeNull()
        ->and(Credential::query()->findOrFail($result?->mint->summary->id)->subject_ref)->toBe('app-b');
});

it('names the mismatched dimensions in a refusal and never their values', function (): void {
    $source = exactTargetSource(['subject_ref' => 'app-b', 'purpose' => CredentialPurpose::Mcp]);
    $target = exactTargetFor();

    $mismatches = $target->mismatchesOf($source);
    $message = null;

    try {
        $target->assertMatches($source);
    } catch (RotationRefused $refusal) {
        $message = $refusal->getMessage();
    }

    expect($mismatches)->toBe(['purpose', 'subject'])
        ->and($message)->toContain('purpose, subject')
        ->and($message)->toContain($source->id)
        ->and($message)->not->toContain('app-b')
        ->and($message)->not->toContain(CredentialPurpose::Mcp->value)
        ->and($target->matches($source))->toBeFalse()
        ->and($target->matches(exactTargetSource(['status' => CredentialStatus::Active])))->toBeTrue();
});
