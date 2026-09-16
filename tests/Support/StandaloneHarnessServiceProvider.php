<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Actions\InstallHmacCredentialFromClaim;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\SourceBoundHmacCutover;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BoundBearerCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\HttpHmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServicePolicyDeclaration;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Notifications\Events\NotificationSent;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;

final class StandaloneHarnessServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app['config']->set('auth.defaults.guard', 'web');
        $this->app['config']->set('auth.guards', [
            'bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        ]);
        $this->app['config']->set('auth.providers', []);
        $this->app['config']->set('cache.default', 'array');
        $this->app['config']->set('built-for-cloud.surfaces.data_migrations', false);

        if (filter_var(env('BFC_HARNESS_PERSONAL_HMAC', false), FILTER_VALIDATE_BOOL)) {
            SelfServicePolicyDeclaration::$kinds = [CredentialKind::Bearer, CredentialKind::Hmac];
            $this->app['config']->set('built-for-cloud.credentials.declaration', SelfServicePolicyDeclaration::class);
        }

        if (getenv('BFC_HARNESS_ASYMMETRIC') !== false) {
            $this->app['config']->set('built-for-cloud.credentials.app_purposes', [
                'reel.application.signing' => CredentialPurpose::Signing->value,
            ]);
        }

        if (getenv('BFC_HARNESS_HMAC_ROLE') !== false) {
            $this->app['config']->set('built-for-cloud.credentials.app_purposes', [
                'matte.callback' => CredentialPurpose::Signing->value,
                'matte.callback.other' => CredentialPurpose::Signing->value,
            ]);
            $this->app['config']->set('built-for-cloud.ui.credential_purposes', ['matte.callback']);
            $this->app['config']->set('cache.default', 'file');
            $this->app['config']->set('cache.stores.file.path', (string) getenv('BFC_HARNESS_CACHE_PATH'));
        }

        if (getenv('BFC_HARNESS_DEVICE_AUTHORIZATION') !== false) {
            $this->app['config']->set('database.connections.sqlite.transaction_mode', 'IMMEDIATE');
            $this->app['config']->set('database.connections.sqlite.busy_timeout', 10_000);
            $profiles = [];

            foreach (['live.device', 'live.loopback'] as $purpose) {
                $profiles[] = new CredentialAuthorizationProfile(
                    $purpose,
                    new BoundCredentialScope(
                        $purpose,
                        new Subject(SubjectType::Installation, 'device-live-installation'),
                        'install_device_live',
                        'app_device_live',
                        'https://device-live.example',
                    ),
                    CredentialAuthorizationOwnership::Installation,
                    [],
                    null,
                    60,
                    5,
                );
            }

            DeviceFlowDeclaration::$profiles = $profiles;
            DeviceFlowDeclaration::$resolvedSubject = null;
            DeviceFlowDeclaration::$authorizeCalls = 0;
            DeviceFlowDeclaration::$authorizedCredentialId = null;
            $this->app['config']->set('built-for-cloud.credentials.declaration', DeviceFlowDeclaration::class);
            $this->app['config']->set('built-for-cloud.credentials.app_purposes', [
                'live.device' => CredentialPurpose::Consumption->value,
                'live.loopback' => CredentialPurpose::Consumption->value,
            ]);
            $this->app['config']->set('cache.default', 'file');
            $this->app['config']->set('cache.stores.file.path', (string) getenv('BFC_HARNESS_CACHE_PATH'));
        }
    }

    public function boot(): void
    {
        if (getenv('BFC_HARNESS_DEVICE_AUTHORIZATION') !== false) {
            DB::listen(static function (QueryExecuted $query): void {
                $credentialId = DeviceFlowDeclaration::$authorizedCredentialId;
                $sql = strtolower($query->sql);

                if ($credentialId === null
                    || ! str_contains($sql, 'update "credentials"')
                    || ! str_contains($sql, 'last_used_at')
                    || ! Schema::hasTable('bfc_device_harness_effects')) {
                    return;
                }

                DB::table('bfc_device_harness_effects')
                    ->where('credential_id', $credentialId)
                    ->increment('usage_calls');
            });

            Route::post('/_bfc-harness/device/use/{profile}', static function (Request $request, string $profile) {
                $purpose = match ($profile) {
                    'device' => 'live.device',
                    'loopback' => 'live.loopback',
                    default => null,
                };

                if ($purpose === null) {
                    abort(404);
                }

                $mapping = config('built-for-cloud.credentials.app_purposes');

                if ($request->header('X-Bfc-Harness-App-Purpose-Mapping') === 'drift') {
                    config()->set('built-for-cloud.credentials.app_purposes', [
                        'live.device' => CredentialPurpose::Mcp->value,
                        'live.loopback' => CredentialPurpose::Consumption->value,
                    ]);
                }

                try {
                    $credential = app(BoundBearerCredentialAuthenticator::class)->authenticate($request, $purpose);
                } finally {
                    config()->set('built-for-cloud.credentials.app_purposes', $mapping);
                }

                if ($credential !== null && Schema::hasTable('bfc_device_harness_effects')) {
                    RateLimiter::hit('bfc-device-harness-use|'.$credential->id, 60);
                    DB::table('bfc_device_harness_effects')
                        ->where('credential_id', $credential->id)
                        ->increment('domain_handler_calls');
                }

                return $credential === null
                    ? response()->json(['authenticated' => false], 401)
                    : response()->json(['authenticated' => true, 'credential_id' => $credential->id]);
            });
            Route::post('/_bfc-harness/device/use-legacy', static function (Request $request) {
                $credential = app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $request->bearerToken());

                return response()->json(['authenticated' => $credential !== null], $credential === null ? 401 : 200);
            });
            Route::get('/_bfc-harness/device/effects/{credential}', static function (string $credential) {
                $row = Credential::query()->findOrFail($credential);
                $effects = DB::table('bfc_device_harness_effects')
                    ->where('credential_id', $credential)
                    ->firstOrFail();

                return response()->json([
                    'authorize_calls' => (int) $effects->authorize_calls,
                    'limiter_attempts' => RateLimiter::attempts('bfc-device-harness-use|'.$credential),
                    'usage_calls' => (int) $effects->usage_calls,
                    'last_used_at' => $row->last_used_at?->toAtomString(),
                    'client_identity' => $row->client_identity,
                    'domain_handler_calls' => (int) $effects->domain_handler_calls,
                ]);
            });
        }

        if (getenv('BFC_HARNESS_ASYMMETRIC') === 'bound') {
            $scope = new BoundCredentialScope(
                'reel.application.signing',
                new Subject(SubjectType::Installation, 'reel-live-installation'),
                'install_live_1',
                'app_live_1',
                'https://reel-live.example',
            );
            $this->app->instance(ResolvesAsymmetricEnrollmentScope::class, new class($scope) implements ResolvesAsymmetricEnrollmentScope
            {
                public function __construct(private readonly BoundCredentialScope $scope) {}

                public function resolve(Request $request, string $application): ?BoundCredentialScope
                {
                    return $application === $this->scope->application ? $this->scope : null;
                }
            });
        }

        if (getenv('BFC_HARNESS_HMAC_ROLE') !== false) {
            $scope = static fn (): BoundCredentialScope => new BoundCredentialScope(
                'matte.callback',
                new Subject(SubjectType::Installation, 'matte-live-installation'),
                'install_live_hmac',
                'app_live_hmac',
                'https://receiver-live.example',
            );

            if (getenv('BFC_HARNESS_HMAC_ROLE') === 'issuer') {
                Route::post('/__harness/hmac/mint', function () use ($scope) {
                    $mint = app(MintCredential::class)(
                        $scope()->subject,
                        new MintOptions(
                            kind: CredentialKind::Hmac,
                            purpose: CredentialPurpose::Signing,
                            codeTtlSeconds: 3600,
                            boundScope: $scope(),
                        ),
                    );
                    $canary = getenv('BFC_HARNESS_HMAC_CANARY');

                    if (is_string($canary) && preg_match('/\A[0-9a-f]{64}\z/D', $canary) === 1) {
                        $encrypted = app(HmacKeyring::class)->encrypt($canary);
                        Credential::query()->whereKey($mint->summary->id)->update([
                            'secret_ciphertext' => $encrypted->ciphertext,
                            'secret_key_version' => $encrypted->keyVersion,
                        ]);
                    }

                    return response()->json([
                        'credential_id' => $mint->summary->id,
                        'claim_code' => $mint->secret?->reveal(),
                    ], 201)->header('Cache-Control', 'no-store');
                });

                Route::post('/__harness/hmac/sign', function (Request $request) use ($scope) {
                    $body = $request->input('body');
                    $event = $request->input('event');

                    abort_unless(is_string($body) && is_string($event), 422);

                    return response()->json([
                        'header' => app(HmacSigner::class)->signBound($scope(), $body, $event),
                    ])->header('Cache-Control', 'no-store');
                });

                Route::post('/__harness/hmac/activate', function (Request $request) use ($scope) {
                    $replacement = $request->input('replacement_id');
                    $fingerprint = $request->input('delivery_fingerprint');
                    abort_unless(is_string($replacement) && is_string($fingerprint), 422);
                    $receipt = app(SourceBoundHmacCutover::class)->activate($scope(), null, $replacement, $fingerprint);

                    return response()->json(['credential_id' => $receipt->replacementCredentialId]);
                });
            }

            if (getenv('BFC_HARNESS_HMAC_ROLE') === 'receiver') {
                Route::post('/__harness/hmac/install', function (Request $request) use ($scope) {
                    $claimCode = $request->input('claim_code');
                    $issuerOrigin = $request->input('issuer_origin');
                    abort_unless(is_string($claimCode) && is_string($issuerOrigin), 422);
                    $client = new HttpHmacCredentialIssuerClient(
                        app(Factory::class),
                        $issuerOrigin,
                        static fn (): array => ['Authorization' => 'Bearer harness-only'],
                    );
                    $result = app(InstallHmacCredentialFromClaim::class)($scope(), $client, $claimCode);

                    $credential = Credential::query()->findOrFail($result->credentialId);

                    return response()->json([
                        'credential_id' => $result->credentialId,
                        'delivery_fingerprint' => $credential->delivery_fingerprint,
                    ], 201)
                        ->header('Cache-Control', 'no-store');
                });

                Route::post('/__harness/hmac/callback', function (Request $request) use ($scope) {
                    $header = $request->input('header');
                    $body = $request->input('body');
                    $mutation = $request->input('scope_mutation');
                    abort_unless(is_string($header) && is_string($body) && ($mutation === null || is_string($mutation)), 422);
                    $expected = match ($mutation) {
                        'purpose' => new BoundCredentialScope('matte.callback.other', $scope()->subject, $scope()->installation, $scope()->application, $scope()->audience),
                        'subject' => new BoundCredentialScope($scope()->appPurpose, new Subject(SubjectType::Installation, 'wrong-subject'), $scope()->installation, $scope()->application, $scope()->audience),
                        'installation' => new BoundCredentialScope($scope()->appPurpose, $scope()->subject, 'wrong-installation', $scope()->application, $scope()->audience),
                        'application' => new BoundCredentialScope($scope()->appPurpose, $scope()->subject, $scope()->installation, 'wrong-application', $scope()->audience),
                        'audience' => new BoundCredentialScope($scope()->appPurpose, $scope()->subject, $scope()->installation, $scope()->application, 'https://wrong.example'),
                        default => $scope(),
                    };

                    try {
                        $verified = app(HmacVerifier::class)->verifyBound($expected, $header, $body);
                    } catch (\Throwable) {
                        return response()->json(['dispatched' => false], 403);
                    }

                    DB::table('bfc_hmac_harness_dispatches')->insert([
                        'credential_id' => $verified->credentialId,
                        'body_hash' => hash('sha256', $body),
                    ]);

                    return response()->json(['dispatched' => true], 202);
                });
            }
        }

        Event::listen(NotificationSent::class, function (NotificationSent $event): void {
            if (! $event->notification instanceof HumanInvitationNotification
                && ! $event->notification instanceof StandalonePasswordResetNotification) {
                return;
            }

            $url = $event->notification->toMail(new AnonymousNotifiable)->actionUrl;

            if (is_string($url) && ! headers_sent()) {
                header('X-Bfc-Harness-Mail: '.$url);
            }
        });
    }
}
