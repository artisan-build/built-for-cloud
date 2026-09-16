<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\CacheBasedSessionHandler;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\FileSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

uses(RefreshDatabase::class);

it('persists only sealed live bindings across regeneration for every supported session shape', function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$selfServiceAbilities = [];
    DeviceFlowDeclaration::$selfServiceKinds = [CredentialKind::Bearer];
    config([
        'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => [
            'session.device' => CredentialPurpose::Consumption->value,
        ],
    ]);
    $user = User::query()->create([
        'name' => 'Session shape operator',
        'email' => 'session-shape@example.test',
        'password' => bcrypt('test-created-password'),
    ]);
    $profile = new CredentialAuthorizationProfile(
        'session.device',
        new BoundCredentialScope(
            'session.device',
            new Subject(SubjectType::UserPrincipal, 'session-user:'.$user->getKey()),
            'session-installation',
            'session-application',
            'https://session-audience.example.test',
        ),
        CredentialAuthorizationOwnership::Personal,
        [],
        null,
        600,
        5,
    );
    DeviceFlowDeclaration::$profiles = [$profile];
    DeviceFlowDeclaration::$resolvedSubject = $profile->scope->subject;
    $this->actingAsVersioned($user, 'web');
    $actionRequest = request();
    $actionRequest->setUserResolver(static fn (): User => $user);
    $actionRequest->setLaravelSession(app('session')->driver());
    $start = app(StartDeviceAuthorization::class)($actionRequest, 'session.device');
    $deviceCode = $start->deviceCode->reveal();
    $userCode = $start->userCode->reveal();
    $browserNonce = $start->browserNonce->reveal();
    $directory = sys_get_temp_dir().'/bfc-device-session-'.bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    $files = new Filesystem;

    try {
        foreach (['database', 'redis', 'file', 'cookie'] as $driver) {
            DB::table('credential_authorizations')->where('id', $start->authorizationId)->update([
                'status' => 'pending',
                'denial_reason' => null,
                'decided_at' => null,
            ]);
            $cookieJar = app('cookie');
            $cookieJar->flushQueuedCookies();
            $handler = match ($driver) {
                'database' => new DatabaseSessionHandler(DB::connection(), 'sessions', 120),
                'redis' => new CacheBasedSessionHandler(new Repository(new ArrayStore), 120),
                'file' => new FileSessionHandler($files, $directory, 120),
                'cookie' => new CookieSessionHandler($cookieJar, 120),
            };

            if ($handler instanceof CookieSessionHandler) {
                $handler->setRequest(new SymfonyRequest);
            }

            $session = new Store('bfc-'.$driver, $handler);
            $session->setId(bin2hex(random_bytes(20)));
            $session->start();
            $request = Request::create('/bfc/device');
            $request->setUserResolver(static fn (): User => $user);
            $request->setLaravelSession($session);
            $browser = app(BrowserCredentialAuthorizationStore::class);
            $browser->putDevice($request, $start->authorizationId, $browserNonce, $userCode);
            $ciphertext = $browser->serializedCiphertexts($request)[0];
            $session->save();

            $read = static function (string $id) use ($driver, $handler, $cookieJar): string {
                if ($driver !== 'cookie') {
                    return (string) $handler->read($id);
                }

                $cookie = $cookieJar->queued($id);
                $value = $cookie instanceof Cookie ? json_decode($cookie->getValue(), true) : null;

                return is_array($value) && is_string($value['data'] ?? null) ? $value['data'] : '';
            };
            $persisted = $read($session->getId());
            expect($persisted)->toContain($ciphertext)
                ->not->toContain($start->authorizationId, $deviceCode, $userCode, $browserNonce);

            $oldId = $session->getId();
            expect($browser->regenerate($request))->toBeTrue();
            $newId = $session->getId();
            $session->save();
            expect($newId)->not->toBe($oldId)
                ->and($read($newId))->toContain($ciphertext)
                ->not->toContain($start->authorizationId, $deviceCode, $userCode, $browserNonce);

            DB::table('credential_authorizations')->where('id', $start->authorizationId)->update([
                'status' => 'denied',
                'denial_reason' => 'authority_denied',
                'decided_at' => now(),
            ]);
            $session->put('bfc_selected_loopback_authorization', 'test-created-stale-selection');
            expect($browser->deviceBindings($request))->toBe([]);
            $session->save();
            expect($session->has('bfc_selected_loopback_authorization'))->toBeFalse()
                ->and($read($newId))->not->toContain($ciphertext, 'bfc_credential_authorizations', 'test-created-stale-selection');
        }
    } finally {
        $files->deleteDirectory($directory);
    }
});
