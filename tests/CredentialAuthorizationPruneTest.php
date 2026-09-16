<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Console\Scheduling\CallbackEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$resolvedSubject = null;
    DeviceFlowDeclaration::$selfServiceAbilities = [];
    DeviceFlowDeclaration::$selfServiceKinds = [CredentialKind::Bearer];
    config([
        'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => ['prune.device' => CredentialPurpose::Consumption->value],
    ]);
});

function pruneAuthorizationContext(object $test): array
{
    $user = User::query()->create([
        'name' => 'Prune operator',
        'email' => 'prune@example.test',
        'password' => bcrypt('test-created-password'),
    ]);
    $profile = new CredentialAuthorizationProfile(
        'prune.device',
        new BoundCredentialScope(
            'prune.device',
            new Subject(SubjectType::UserPrincipal, 'prune-user:'.$user->getKey()),
            'prune-installation',
            'prune-application',
            'https://prune-audience.example.test',
        ),
        CredentialAuthorizationOwnership::Personal,
        [],
        now()->addDay(),
        600,
        5,
    );
    DeviceFlowDeclaration::$profiles = [$profile];
    DeviceFlowDeclaration::$resolvedSubject = $profile->scope->subject;
    $test->actingAsVersioned($user, 'web');
    $request = request();
    $request->setUserResolver(static fn (): User => $user);
    $request->setLaravelSession(app('session')->driver());

    return [$user, $request];
}

it('prunes only rows past the exact retention clocks and preserves the durable credential', function (): void {
    [, $request] = pruneAuthorizationContext($this);
    $consumed = app(StartDeviceAuthorization::class)($request, 'prune.device', 'Consumed grant');
    $deviceCode = $consumed->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $consumed->userCode->reveal(), $consumed->browserNonce->reveal(), true);
    $token = app(PollDeviceAuthorization::class)($request, $deviceCode);
    $credentialId = $token->credentialId;

    $pending = app(StartDeviceAuthorization::class)($request, 'prune.device', 'Pending grant');
    $pending->deviceCode->reveal();
    $pending->userCode->reveal();
    $pending->browserNonce->reveal();
    $denied = app(StartDeviceAuthorization::class)($request, 'prune.device', 'Denied grant');
    $denied->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $denied->userCode->reveal(), $denied->browserNonce->reveal(), false);
    $live = app(StartDeviceAuthorization::class)($request, 'prune.device', 'Retained grant');
    $live->deviceCode->reveal();
    $live->userCode->reveal();
    $live->browserNonce->reveal();

    $eligible = now()->subDay()->subSecond();
    DB::table('credential_authorizations')->where('id', $consumed->authorizationId)->update(['consumed_at' => $eligible]);
    DB::table('credential_authorizations')->where('id', $pending->authorizationId)->update(['expires_at' => $eligible]);
    DB::table('credential_authorizations')->where('id', $denied->authorizationId)->update(['decided_at' => $eligible]);
    DB::table('credential_authorizations')->where('id', $live->authorizationId)->update(['expires_at' => now()->subDay()->addSecond()]);

    $this->artisan('bfc:credential-authorizations:prune --local')
        ->expectsOutput('Pruned 3 credential authorization row(s).')
        ->assertSuccessful();

    expect(DB::table('credential_authorizations')->pluck('id')->all())->toBe([$live->authorizationId])
        ->and(DB::table('credentials')->where('id', $credentialId)->exists())->toBeTrue()
        ->and(DB::table('credential_audit_events')->where('credential_authorization_id', $consumed->authorizationId)->exists())->toBeTrue();
});

it('requires local mode and registers the hourly local system command', function (): void {
    pruneAuthorizationContext($this);
    $this->artisan('bfc:credential-authorizations:prune')->assertFailed();

    $events = app(Schedule::class)->events();
    $event = collect($events)->first(static fn ($event): bool => $event->description === 'bfc-credential-authorizations-prune');

    expect($event)->not->toBeNull()
        ->and($event->expression)->toBe('0 * * * *')
        ->and($event)->toBeInstanceOf(CallbackEvent::class);
});

it('prunes eligible rows in batches larger than five hundred', function (): void {
    [, $request] = pruneAuthorizationContext($this);
    $seed = app(StartDeviceAuthorization::class)($request, 'prune.device', 'Batch seed');
    $seed->deviceCode->reveal();
    $seed->userCode->reveal();
    $seed->browserNonce->reveal();
    $row = (array) DB::table('credential_authorizations')->where('id', $seed->authorizationId)->sole();
    DB::table('credential_authorizations')->where('id', $seed->authorizationId)->delete();
    $rows = [];

    for ($i = 0; $i < 501; $i++) {
        $rows[] = [
            ...$row,
            'id' => (string) Str::uuid(),
            'device_code_hash' => hash('sha256', 'device-'.$i),
            'user_code_hash' => hash('sha256', 'user-'.$i),
            'expires_at' => now()->subDay()->subSeconds(501 - $i),
        ];
    }

    foreach (array_chunk($rows, 100) as $chunk) {
        DB::table('credential_authorizations')->insert($chunk);
    }

    $this->artisan('bfc:credential-authorizations:prune --local')
        ->expectsOutput('Pruned 501 credential authorization row(s).')
        ->assertSuccessful();
    expect(DB::table('credential_authorizations')->count())->toBe(0);
});
