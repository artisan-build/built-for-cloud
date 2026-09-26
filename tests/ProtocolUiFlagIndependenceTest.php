<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacSigningRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacVerificationFailed;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

uses(RefreshDatabase::class);

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function p5gConfigureUi(bool $enabled): void
{
    config([
        'built-for-cloud.ui.member_management' => $enabled,
        'built-for-cloud.ui.personal_credentials' => $enabled,
        'built-for-cloud.ui.installation_credentials' => $enabled,
        'built-for-cloud.ui.session_management' => $enabled,
        'built-for-cloud.ui.managed_transitions' => $enabled,
        'built-for-cloud.ui.credential_purposes' => $enabled ? ['test-app.consumption'] : [],
        'built-for-cloud.credentials.app_purposes' => $enabled ? ['test-app.consumption' => CredentialPurpose::Consumption->value] : [],
    ]);
}

/** @return array<string, int> */
function p5gEffectCounts(): array
{
    return [
        'credential_audits' => DB::table('credential_audit_events')->count(),
        'credential_outbox' => DB::table('credential_outbox')->count(),
        'app_action_audits' => DB::table('bfc_app_action_events')->count(),
        'app_action_outbox' => DB::table('bfc_app_action_outbox')->count(),
    ];
}

/** @return array<string, int> */
function p5gProtectedCounts(): array
{
    return [
        'credentials' => DB::table('credentials')->count(),
        'onboarding_tokens' => DB::table('onboarding_tokens')->count(),
        'users' => DB::table('users')->count(),
        'authority' => DB::table('bfc_authority')->count(),
        'console_keys' => DB::table('bfc_console_keys')->count(),
        'assertion_burns' => DB::table('bfc_console_assertion_burns')->count(),
        'delegated_actors' => DB::table('bfc_delegated_actors')->count(),
        'client_observations' => DB::table('bfc_client_identity_observations')->count(),
    ];
}

/**
 * @param  array<string, int>  $after
 * @param  array<string, int>  $before
 * @return array<string, int>
 */
function p5gDelta(array $after, array $before): array
{
    $delta = [];

    foreach ($after as $key => $value) {
        $delta[$key] = $value - $before[$key];
    }

    return $delta;
}

/** @return array<string, mixed> */
function p5gCredentialState(Credential $credential): array
{
    $row = DB::table('credentials')->where('id', $credential->id)->first();

    return [
        'exists' => $row !== null,
        'purpose' => $row?->purpose,
        'status' => $row?->status,
        'revoked' => $row?->revoked_at !== null,
        'expired' => $row?->expires_at !== null,
        'used' => $row?->last_used_at !== null,
        'client_identity' => $row?->client_identity,
        'client_identity_seen' => $row?->client_identity_last_seen_at !== null,
        'secret_key_version' => $row?->secret_key_version,
    ];
}

/** @return array{refusal_class: string, status: int|null, message: string, reason: string|null, disclosed_downstream: bool} */
function p5gCapture(callable $operation): array
{
    try {
        $result = $operation();
        $message = $result instanceof Response ? (string) $result->getContent() : '';

        return [
            'refusal_class' => $result instanceof Response ? $result::class : 'return:'.get_debug_type($result),
            'status' => $result instanceof Response ? $result->getStatusCode() : null,
            'message' => $message,
            'reason' => null,
            'disclosed_downstream' => str_contains($message, 'p5g-downstream-secret'),
        ];
    } catch (Throwable $exception) {
        $reason = property_exists($exception, 'reason') ? $exception->reason : null;

        if ($reason instanceof BackedEnum) {
            $reason = $reason->value;
        }

        return [
            'refusal_class' => $exception::class,
            'status' => $exception instanceof HttpExceptionInterface ? $exception->getStatusCode() : null,
            'message' => $exception->getMessage(),
            'reason' => is_string($reason) ? $reason : null,
            'disclosed_downstream' => str_contains($exception->getMessage(), 'p5g-downstream-secret'),
        ];
    }
}

/**
 * @param  callable(): mixed  $operation
 * @param  callable(): array<string, mixed>  $protectedState
 * @param  callable(): int  $downstreamCount
 * @return array<string, mixed>
 */
function p5gObserve(callable $operation, callable $protectedState, callable $downstreamCount): array
{
    $protectedBefore = $protectedState();
    $protectedCounts = p5gProtectedCounts();
    $effects = p5gEffectCounts();
    $refusal = p5gCapture($operation);

    return [
        ...$refusal,
        'protected_state_before' => $protectedBefore,
        'protected_state_after' => $protectedState(),
        'protected_table_delta' => p5gDelta(p5gProtectedCounts(), $protectedCounts),
        'audit_delivery_delta' => p5gDelta(p5gEffectCounts(), $effects),
        'downstream_invocations' => $downstreamCount(),
    ];
}

/** @return array{Credential, string} */
function p5gStoredCredential(CredentialKind $kind, ?CredentialPurpose $storedPurpose): array
{
    $secret = 'p5g-'.bin2hex(random_bytes(24));
    $credential = Credential::query()->create([
        'kind' => $kind,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'p5g-protocol-subject',
        'name' => 'P5g protocol refusal',
        'abilities' => [OperatorAbility::Admin->value, OperatorAbility::McpRead->value],
        'secret_hash' => hash('sha256', $secret),
    ]);
    DB::table('credentials')->where('id', $credential->id)->update([
        'purpose' => $storedPurpose?->value,
    ]);

    return [$credential, $secret];
}

/** @return array<string, mixed> */
function p5gPurposeOutcome(bool $enabled, string $caller, ?CredentialPurpose $storedPurpose): array
{
    p5gConfigureUi($enabled);
    $kind = $caller === 'basic' ? CredentialKind::Basic : CredentialKind::Bearer;
    [$credential, $secret] = p5gStoredCredential($kind, $storedPurpose);
    $downstream = 0;
    $request = Request::create('/_p5g/'.$caller, 'POST', server: [
        'HTTP_AUTHORIZATION' => $kind === CredentialKind::Basic
            ? 'Basic '.base64_encode('ignored:'.$secret)
            : 'Bearer '.$secret,
        'HTTP_X_BFC_CLIENT_ID' => 'p5g-protected-client',
    ]);

    $operation = match ($caller) {
        'basic', 'bearer' => function () use ($caller, $enabled, $kind, $secret, &$downstream): Response {
            config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null]]);
            Auth::forgetGuards();
            $uri = '/_p5g/'.$caller.'/'.($enabled ? 'on' : 'off').'/'.bin2hex(random_bytes(4));
            Route::middleware('auth:bfc')->get($uri, function () use (&$downstream): string {
                $downstream++;

                return 'p5g-downstream-secret';
            });
            $header = $kind === CredentialKind::Basic
                ? 'Basic '.base64_encode('ignored:'.$secret)
                : 'Bearer '.$secret;

            return test()->getJson($uri, ['Authorization' => $header])->baseResponse;
        },
        'guard-validate' => function () use ($secret, &$downstream): bool {
            config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null]]);
            Auth::forgetGuards();
            /** @var CredentialGuard $guard */
            $guard = Auth::guard('bfc');
            $accepted = $guard->validate(['secret' => $secret]);
            $downstream += (int) $accepted;

            return $accepted;
        },
        'onboarding' => function () use ($request, &$downstream): Response {
            $response = app(ManageOnboarding::class)->verify($request);
            $downstream += (int) $response->isSuccessful();

            return $response;
        },
        'mcp' => fn (): Response => app(AuthenticateMcp::class)->handle(
            $request,
            function () use (&$downstream): Response {
                $downstream++;

                return response('p5g-downstream-secret');
            },
        ),
        'operator' => fn (): Response => app(EnsureCredentialAdmin::class)->handle(
            $request,
            function () use (&$downstream): Response {
                $downstream++;

                return response('p5g-downstream-secret');
            },
            OperatorAbility::CredentialRead->value,
        ),
    };

    return p5gObserve(
        $operation,
        fn (): array => [
            'credential' => p5gCredentialState($credential),
            'request_actor' => $request->attributes->has('bfc.actor_credential_id'),
            'request_user' => $request->getUserResolver() !== null && $request->user() !== null,
        ],
        fn (): int => $downstream,
    );
}

/**
 * @param  array<string, mixed>|string  $mappings
 * @return array<string, mixed>
 */
function p5gAppPurposeOutcome(bool $enabled, array|string $mappings): array
{
    p5gConfigureUi($enabled);
    config(['built-for-cloud.credentials.app_purposes' => $mappings]);
    $downstream = 0;

    return p5gObserve(
        function () use (&$downstream): CredentialPurpose {
            $purpose = app(AppPurposeRegistry::class)->purpose('test-app.consumption');
            $downstream++;

            return $purpose;
        },
        static fn (): array => [],
        fn (): int => $downstream,
    );
}

function p5gHmacHeader(Credential $credential, string $body, string $audience): string
{
    $envelope = new HmacEnvelope(
        keyId: $credential->id,
        eventType: 'p5g.test',
        timestamp: now()->getTimestamp(),
        nonce: bin2hex(random_bytes(16)),
        audience: $audience,
    );
    $key = app(HmacKeyring::class)->decrypt((string) $credential->secret_ciphertext, $credential->secret_key_version);

    return $envelope->headerValue(hash_hmac('sha256', $envelope->canonical($body), $key));
}

/** @return array<string, mixed> */
function p5gOrdinaryHmacOutcome(bool $enabled, string $selector, ?CredentialPurpose $storedPurpose): array
{
    p5gConfigureUi($enabled);
    $subject = new Subject(SubjectType::ExternalConsumer, 'p5g-ordinary-'.$selector);
    $credential = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $subject->type,
        'subject_ref' => $subject->ref,
    ]);
    $header = p5gHmacHeader($credential, 'p5g body', (string) config('built-for-cloud.hmac.audience'));
    DB::table('credentials')->where('id', $credential->id)->update([
        'purpose' => $storedPurpose?->value,
        'secret_key_version' => 'p5g-purpose-gate-must-precede-decrypt',
    ]);
    $downstream = 0;

    return p5gObserve(
        function () use ($selector, $subject, $header, &$downstream): mixed {
            $result = $selector === 'signer'
                ? app(HmacSigner::class)->sign($subject, 'p5g body', 'p5g.test')
                : app(HmacVerifier::class)->verify($subject, $header, 'p5g body');
            $downstream++;

            return $result;
        },
        fn (): array => p5gCredentialState($credential),
        fn (): int => $downstream,
    );
}

/** @return array<string, mixed> */
function p5gRootOutcome(bool $enabled, string $selector, ?CredentialPurpose $storedPurpose): array
{
    p5gConfigureUi($enabled);
    Credential::query()->delete();
    $credential = Credential::factory()->hmac()->activated()->create([
        'purpose' => CredentialPurpose::SigningRoot,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => SigningRootMac::SUBJECT_REF,
        'abilities' => null,
        'user_id' => null,
    ]);
    $valid = app(SigningRootMac::class)->mac('p5g root bytes');
    DB::table('credentials')->where('id', $credential->id)->update([
        'purpose' => $storedPurpose?->value,
        'secret_key_version' => 'p5g-root-gate-must-precede-decrypt',
    ]);
    $downstream = 0;

    return p5gObserve(
        function () use ($selector, $valid, &$downstream): mixed {
            $result = $selector === 'mac'
                ? app(SigningRootMac::class)->mac('p5g root bytes')
                : app(SigningRootMac::class)->verify($valid->keyId, 'p5g root bytes', $valid->lowercaseHexMac);
            $downstream += (int) ($selector === 'mac' || $result === true);

            return $result;
        },
        fn (): array => p5gCredentialState($credential),
        fn (): int => $downstream,
    );
}

/** @return array<string, mixed> */
function p5gResolverLifecycleOutcome(bool $enabled, string $lifecycle): array
{
    p5gConfigureUi($enabled);
    [$credential, $secret] = p5gStoredCredential(CredentialKind::Bearer, CredentialPurpose::Consumption);
    DB::table('credentials')->where('id', $credential->id)->update($lifecycle === 'revoked'
        ? ['revoked_at' => now()]
        : ['expires_at' => now()->subMinute()]);
    $downstream = 0;

    return p5gObserve(
        function () use ($secret, &$downstream): ?Credential {
            $resolved = app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret);
            $downstream += (int) ($resolved instanceof Credential);

            return $resolved;
        },
        fn (): array => p5gCredentialState($credential),
        fn (): int => $downstream,
    );
}

function p5gManagedAuthority(): void
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'p5g-connection',
        'organization_id' => 'p5g-organization',
        'installation_id' => 'p5g-installation',
        'authority_base_url' => 'https://authority.example.test',
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
        'managed_connection_roster_version' => 11,
        'managed_connection_response_sequence' => 11,
    ]);
    config(['built-for-cloud.managed.client_secret' => 'p5g-test-client-secret']);
}

/** @return array<string, mixed> */
function p5gManagedBindingOutcome(bool $enabled): array
{
    p5gConfigureUi($enabled);
    p5gManagedAuthority();
    $user = User::query()->create([
        'name' => 'P5g managed binding',
        'email' => 'p5g-managed-'.($enabled ? 'on' : 'off').'@example.test',
    ]);
    $user->forceFill([
        'role' => 'admin',
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $user->email,
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'wrong-p5g-connection',
        'scalpels_id' => 'p5g-managed-subject-'.($enabled ? 'on' : 'off'),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'admin',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 11,
        'managed_membership_response_sequence' => 11,
        'managed_membership_responded_at' => now(),
        'membership_confirmed_at' => now(),
    ])->save();
    [$credential] = p5gStoredCredential(CredentialKind::Bearer, CredentialPurpose::Consumption);
    DB::table('credentials')->where('id', $credential->id)->update(['user_id' => (string) $user->id]);
    $downstream = 0;

    return p5gObserve(
        function () use ($credential, &$downstream): bool {
            $allowed = app(ManagedAccountAccess::class)->allowsCredential($credential->fresh());
            $downstream += (int) $allowed;

            return $allowed;
        },
        fn (): array => [
            'credential' => p5gCredentialState($credential),
            'user' => [
                'status' => $user->fresh()->status,
                'role' => $user->role,
                'connection_id' => $user->scalpels_connection_id,
                'membership_status' => $user->managed_membership_status,
            ],
        ],
        fn (): int => $downstream,
    );
}

/** @return array<string, mixed> */
function p5gWrongHmacAudienceOutcome(bool $enabled): array
{
    p5gConfigureUi($enabled);
    $subject = new Subject(SubjectType::ExternalConsumer, 'p5g-wrong-audience');
    $credential = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $subject->type,
        'subject_ref' => $subject->ref,
    ]);
    $header = p5gHmacHeader($credential, 'p5g audience body', 'https://other-installation.example');
    DB::table('credentials')->where('id', $credential->id)->update([
        'secret_key_version' => 'p5g-audience-gate-must-precede-decrypt',
    ]);
    $downstream = 0;

    return p5gObserve(
        function () use ($subject, $header, &$downstream): Credential {
            $verified = app(HmacVerifier::class)->verify($subject, $header, 'p5g audience body');
            $downstream++;

            return $verified;
        },
        fn (): array => p5gCredentialState($credential),
        fn (): int => $downstream,
    );
}

/** @return array<string, mixed> */
function p5gWrongConsoleAudienceOutcome(bool $enabled): array
{
    p5gConfigureUi($enabled);
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);
    $keyId = 'p5g-console-'.($enabled ? 'on' : 'off');
    $secret = consoleKeypair();
    $key = consoleFileKey($keyId, $secret);
    $token = consoleMint($secret, consoleClaims(['aud' => 'https://other-installation.example']), $keyId);
    $downstream = 0;

    return p5gObserve(
        function () use ($token, &$downstream): mixed {
            $assertion = app(AssertionVerifier::class)->verify($token);
            $downstream++;

            return $assertion;
        },
        fn (): array => [
            'key_status' => $key->fresh()->status,
            'retired' => $key->retired_at !== null,
        ],
        fn (): int => $downstream,
    );
}

it('keeps wrong and missing purpose refusals identical through every resolver caller and ordinary selector', function (string $caller, ?CredentialPurpose $storedPurpose): void {
    CarbonImmutable::setTestNow('2026-09-14T12:00:00+00:00');
    $off = in_array($caller, ['signer', 'verifier'], true)
        ? p5gOrdinaryHmacOutcome(false, $caller, $storedPurpose)
        : p5gPurposeOutcome(false, $caller, $storedPurpose);
    $on = in_array($caller, ['signer', 'verifier'], true)
        ? p5gOrdinaryHmacOutcome(true, $caller, $storedPurpose)
        : p5gPurposeOutcome(true, $caller, $storedPurpose);
    $expectedClass = match ($caller) {
        'basic', 'bearer', 'onboarding', 'mcp' => JsonResponse::class,
        'guard-validate' => 'return:bool',
        'operator' => HttpException::class,
        'signer' => HmacSigningRefused::class,
        'verifier' => HmacVerificationFailed::class,
    };
    $expectedStatus = match ($caller) {
        'basic', 'bearer', 'mcp', 'operator' => 401,
        'onboarding' => 404,
        default => null,
    };

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe($expectedClass)
        ->and($off['status'])->toBe($expectedStatus)
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
})->with([
    'Basic wrong purpose' => ['basic', CredentialPurpose::DashboardMetadata],
    'Basic missing purpose' => ['basic', null],
    'Bearer wrong purpose' => ['bearer', CredentialPurpose::DashboardMetadata],
    'Bearer missing purpose' => ['bearer', null],
    'guard validate wrong purpose' => ['guard-validate', CredentialPurpose::DashboardMetadata],
    'guard validate missing purpose' => ['guard-validate', null],
    'onboarding wrong purpose' => ['onboarding', CredentialPurpose::SystemDeployment],
    'onboarding missing purpose' => ['onboarding', null],
    'MCP wrong purpose' => ['mcp', CredentialPurpose::SystemDeployment],
    'MCP missing purpose' => ['mcp', null],
    'operator gate wrong purpose' => ['operator', CredentialPurpose::Consumption],
    'operator gate missing purpose' => ['operator', null],
    'HMAC signer wrong purpose' => ['signer', CredentialPurpose::Consumption],
    'HMAC signer missing purpose' => ['signer', null],
    'HMAC verifier wrong purpose' => ['verifier', CredentialPurpose::Consumption],
    'HMAC verifier missing purpose' => ['verifier', null],
]);

it('keeps every invalid app-purpose mapping refusal identical with all UI affordances off and on', function (array|string $mappings): void {
    $off = p5gAppPurposeOutcome(false, $mappings);
    $on = p5gAppPurposeOutcome(true, $mappings);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe(InvalidCredentialInput::class)
        ->and($off['status'])->toBeNull()
        ->and($off['message'])->toBe('The app purpose mapping is invalid.')
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
})->with([
    'missing mapping' => [[]],
    'scalar-malformed mapping' => [['test-app.consumption' => 1]],
    'list-valued mapping' => [['test-app.consumption' => [CredentialPurpose::Consumption->value]]],
    'unknown mapping' => [['test-app.consumption' => 'not-a-protocol-purpose']],
]);

it('keeps wrong-purpose root refusals identical with all UI affordances off and on', function (string $selector, ?CredentialPurpose $storedPurpose): void {
    $off = p5gRootOutcome(false, $selector, $storedPurpose);
    $on = p5gRootOutcome(true, $selector, $storedPurpose);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe($selector === 'mac' ? SigningRootRefused::class : 'return:bool')
        ->and($off['status'])->toBeNull()
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
})->with([
    'root MAC wrong purpose' => ['mac', CredentialPurpose::Signing],
    'root verify wrong purpose' => ['verify', CredentialPurpose::Signing],
]);

it('keeps resolver lifecycle refusals identical with all UI affordances off and on', function (string $lifecycle): void {
    $off = p5gResolverLifecycleOutcome(false, $lifecycle);
    $on = p5gResolverLifecycleOutcome(true, $lifecycle);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe('return:null')
        ->and($off['status'])->toBeNull()
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
})->with(['revoked', 'expired']);

it('keeps denied managed binding identical with all UI affordances off and on', function (): void {
    $off = p5gManagedBindingOutcome(false);
    $on = p5gManagedBindingOutcome(true);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe('return:bool')
        ->and($off['status'])->toBeNull()
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
});

it('keeps wrong HMAC audience refusal identical with all UI affordances off and on', function (): void {
    $off = p5gWrongHmacAudienceOutcome(false);
    $on = p5gWrongHmacAudienceOutcome(true);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe(HmacVerificationFailed::class)
        ->and($off['status'])->toBeNull()
        ->and($off['reason'])->toBe('wrong_audience')
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
});

it('keeps wrong console audience refusal identical with all UI affordances off and on', function (): void {
    CarbonImmutable::setTestNow('2026-09-14T12:00:00+00:00');
    $off = p5gWrongConsoleAudienceOutcome(false);
    $on = p5gWrongConsoleAudienceOutcome(true);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe(AssertionRefused::class)
        ->and($off['status'])->toBeNull()
        ->and($off['reason'])->toBe('audience_mismatch')
        ->and($off['protected_state_before'])->toBe($off['protected_state_after'])
        ->and($off['protected_table_delta'])->toBe(array_fill_keys(array_keys(p5gProtectedCounts()), 0))
        ->and($off['audit_delivery_delta'])->toBe(array_fill_keys(array_keys(p5gEffectCounts()), 0))
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0);
});
