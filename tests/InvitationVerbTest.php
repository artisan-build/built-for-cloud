<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * @param  array<string, mixed>  $payload
 * @return TestResponse<Response>
 */
function inviteOverHttp(array $payload): TestResponse
{
    return test()->postJson('/bfc/invitations', $payload, [
        'Authorization' => 'Bearer '.auditAdminToken('invite-admin-'.bin2hex(random_bytes(4))),
    ]);
}

/**
 * @param  array<string, string>  $eventOptions
 * @return TestResponse<Response>
 */
function inviteIntegrationEvent(string $eventId, int $version, array $eventOptions = []): TestResponse
{
    return inviteOverHttp([
        'email' => $eventOptions['email'] ?? 'sponsor@example.test',
        'ttl_seconds' => 3600,
        'integration_namespace' => $eventOptions['namespace'] ?? 'github-sponsors',
        'event_id' => $eventId,
        'entitlement_version' => $version,
        'external_subject' => $eventOptions['subject'] ?? 'sponsor-login',
    ]);
}

// PR8 locked AC 1 (verb path): ttl required and bounded, identically on
// both transports, with no hidden default anywhere.

it('requires ttl_seconds on both transports with the identical refusal', function (): void {
    $httpMissing = inviteOverHttp(['email' => 'ttl@example.test']);
    $httpMissing->assertStatus(422);

    $message = (string) $httpMissing->json('message');
    expect($message)->toContain('ttl_seconds');

    $cliExit = Artisan::call('bfc:invitation:issue', ['--email' => 'ttl@example.test', '--local' => true]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe($message)
        ->and(Invitation::query()->count())->toBe(0);
});

it('rejects out-of-bounds and junk ttls identically on both transports', function (): void {
    foreach ([59, 604801] as $ttl) {
        $http = inviteOverHttp(['email' => 'bounds@example.test', 'ttl_seconds' => $ttl]);
        $http->assertStatus(422);

        $cliExit = Artisan::call('bfc:invitation:issue', [
            '--email' => 'bounds@example.test',
            '--ttl' => (string) $ttl,
            '--local' => true,
        ]);

        expect($cliExit)->toBe(Command::FAILURE)
            ->and(trim(Artisan::output()))->toBe((string) $http->json('message'));
    }

    $junk = inviteOverHttp(['email' => 'junk@example.test', 'ttl_seconds' => '60junk']);
    $junk->assertStatus(422);

    $cliExit = Artisan::call('bfc:invitation:issue', [
        '--email' => 'junk@example.test',
        '--ttl' => '60junk',
        '--local' => true,
    ]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe((string) $junk->json('message'))
        ->and(Invitation::query()->count())->toBe(0);
});

it('issues an addressed invitation over HTTP with the audited single reveal', function (): void {
    $response = inviteOverHttp([
        'email' => 'person@example.test',
        'ttl_seconds' => 3600,
        'invited_by' => '42',
        'role' => 'member',
    ]);

    $response->assertCreated();

    $code = (string) $response->json('invitation_code');

    /** @var Invitation $row */
    $row = Invitation::query()->where('token', hash('sha256', $code))->sole();

    expect($response->json('invitation_id'))->toBe($row->id)
        ->and($response->json('email'))->toBe('person@example.test')
        ->and($row->getAttributes()['email'])->toBe('person@example.test')
        ->and($row->getAttributes()['role'])->toBe('member')
        ->and($row->getAttributes()['invited_by'])->toBe('42');

    $issued = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Issued->value)
        ->where('code_id', $row->id)
        ->sole();

    expect($issued->recipient)->toBe('person@example.test')
        ->and($issued->code_ttl_seconds)->toBe(3600)
        ->and(CredentialOutboxEntry::query()->where('audit_event_id', $issued->id)->exists())->toBeTrue();
});

it('issues an open invitation through the CLI, revealing the code exactly once', function (): void {
    $exitCode = Artisan::call('bfc:invitation:issue', ['--ttl' => '3600', '--local' => true]);
    $output = Artisan::output();

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and(preg_match('/shown once: (\S+)/', $output, $matches))->toBe(1);

    $this->assertRevealsSecretExactlyOnce($output, $matches[1]);

    /** @var Invitation $row */
    $row = Invitation::query()->where('token', hash('sha256', $matches[1]))->sole();

    expect($row->getAttributes()['email'])->toBeNull()
        ->and($output)->toContain('(open)');
});

it('refuses the verb identically on both transports when the matrix denies issue', function (): void {
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return $verb !== CredentialVerb::Issue;
        }
    });

    $http = inviteOverHttp(['email' => 'denied@example.test', 'ttl_seconds' => 3600]);
    $http->assertForbidden();

    $cliExit = Artisan::call('bfc:invitation:issue', [
        '--email' => 'denied@example.test',
        '--ttl' => '3600',
        '--local' => true,
    ]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe((string) $http->json('message'))
        ->and(Invitation::query()->count())->toBe(0);
});

// PR8 locked AC 6: every pairwise ordering through the version gate.

it('applies in-order versions and transactionally ignores an older one', function (): void {
    $first = inviteIntegrationEvent('evt-1', 1);
    $second = inviteIntegrationEvent('evt-2', 2);

    expect($first->json('invitation_id'))->not->toBeNull()
        ->and($second->json('invitation_id'))->not->toBeNull()
        ->and(Invitation::query()->count())->toBe(2);

    // The delayed older event: acknowledged, ignored, nothing issued.
    $late = inviteIntegrationEvent('evt-0', 1);

    $late->assertCreated();

    expect($late->json('invitation_id'))->toBeNull()
        ->and($late->json('invitation_code'))->toBeNull()
        ->and(Invitation::query()->count())->toBe(2)
        ->and(IntegrationEntitlement::query()->sole()->entitlement_version)->toBe(2)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-0')->sole()->applied)->toBeFalse();
});

it('ignores an out-of-order older version arriving first-reversed', function (): void {
    $newer = inviteIntegrationEvent('evt-new', 5);
    $older = inviteIntegrationEvent('evt-old', 3);

    expect($newer->json('invitation_id'))->not->toBeNull()
        ->and($older->json('invitation_id'))->toBeNull()
        ->and(Invitation::query()->count())->toBe(1)
        ->and(IntegrationEntitlement::query()->sole()->entitlement_version)->toBe(5);
});

it('ignores an equal version under a fresh event id — not newer is not applied', function (): void {
    inviteIntegrationEvent('evt-a', 4)->assertCreated();

    $equal = inviteIntegrationEvent('evt-b', 4);

    expect($equal->json('invitation_id'))->toBeNull()
        ->and(Invitation::query()->count())->toBe(1);
});

it('replays a duplicate event id idempotently — same shape, no second invitation', function (): void {
    $original = inviteIntegrationEvent('evt-dup', 1);

    expect($original->json('invitation_id'))->not->toBeNull();

    $replay = inviteIntegrationEvent('evt-dup', 1);

    $replay->assertCreated();

    expect(array_keys((array) $replay->json()))->toBe(array_keys((array) $original->json()))
        ->and($replay->json('invitation_id'))->toBeNull()
        ->and($replay->json('invitation_code'))->toBeNull()
        ->and(Invitation::query()->count())->toBe(1)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-dup')->count())->toBe(1);
});

it('does not resurrect an accepted invitation when its event replays', function (): void {
    $applied = inviteIntegrationEvent('evt-accept', 1);

    $code = (string) $applied->json('invitation_code');

    Invitation::accept($code, ['name' => 'Sponsor', 'password' => 'pw']);

    $replay = inviteIntegrationEvent('evt-accept', 1);

    $replay->assertCreated();

    expect($replay->json('invitation_id'))->toBeNull()
        ->and(Invitation::query()->count())->toBe(1)
        ->and(Invitation::query()->sole()->accepted_at)->not->toBeNull();
});

it('rejects a partial integration-event group identically on both transports', function (): void {
    $http = inviteOverHttp([
        'email' => 'partial@example.test',
        'ttl_seconds' => 3600,
        'integration_namespace' => 'github-sponsors',
        'event_id' => 'evt-partial',
    ]);

    $http->assertStatus(422);

    $cliExit = Artisan::call('bfc:invitation:issue', [
        '--email' => 'partial@example.test',
        '--ttl' => '3600',
        '--integration-namespace' => 'github-sponsors',
        '--event-id' => 'evt-partial',
        '--local' => true,
    ]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe((string) $http->json('message'))
        ->and(Invitation::query()->count())->toBe(0)
        ->and(IntegrationEvent::query()->count())->toBe(0);
});

it('rejects a negative entitlement version and a malformed email as shared input errors', function (): void {
    inviteIntegrationEvent('evt-neg', -1)->assertStatus(422);

    inviteOverHttp(['email' => 'not-an-email', 'ttl_seconds' => 3600])->assertStatus(422);

    expect(Invitation::query()->count())->toBe(0);
});

// PR8 locked AC 7: the non-enumerating shape — exact same keys and status
// for a fresh subject, an already-invited one, and an already-accepted one.

it('answers with one shape whatever the prior state of the invited human', function (): void {
    $fresh = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);
    $reinvited = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);

    Invitation::accept((string) $fresh->json('invitation_code'), ['name' => 'Probe', 'password' => 'pw']);

    $afterAccept = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);

    foreach ([$fresh, $reinvited, $afterAccept] as $response) {
        $response->assertCreated();

        expect(array_keys((array) $response->json()))->toBe(['invitation_id', 'invitation_code', 'email']);
    }
});

it('answers with the same shape and status for applied and ignored integration events', function (): void {
    $applied = inviteIntegrationEvent('evt-shape-1', 2);
    $ignored = inviteIntegrationEvent('evt-shape-0', 1);

    $applied->assertCreated();
    $ignored->assertCreated();

    expect(array_keys((array) $applied->json()))->toBe(array_keys((array) $ignored->json()));
});

// PR8 locked AC 4 (notification side): addressed invitations notify the
// recipient through the policy; unaddressed notify nobody.

it('notifies the addressed recipient through the lifecycle policy, ids only', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.policy.issued', ['holder']);

    $response = inviteOverHttp(['email' => 'notified@example.test', 'ttl_seconds' => 3600]);
    $response->assertCreated();

    $code = (string) $response->json('invitation_code');

    $captured = null;

    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        function (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable) use (&$captured): bool {
            $captured = $notification;

            return $notification->event === 'issued'
                && ($notifiable->routes['mail'] ?? null) === 'notified@example.test';
        },
    );

    // The notice carries the invitation's ID, never the code: the code's
    // one egress is the verb's response, and the caller owns delivering
    // the accept link.
    expect($captured)->not->toBeNull()
        ->and($captured->codeId)->toBe($response->json('invitation_id'));

    $rendered = implode("\n", $captured->toMail(new AnonymousNotifiable)->introLines);

    $this->assertConsoleOutputCarriesNoSecret($rendered, $code);
});

it('notifies nobody for an unaddressed invitation even with the policy row declared', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.notifications.policy.issued', ['holder']);
    config()->set('built-for-cloud.notifications.issuer', 'issuer@example.test');

    Artisan::call('bfc:invitation:issue', ['--ttl' => '3600', '--local' => true]);

    Notification::assertNothingSent();
});

// PR8 locked AC 9 (verb side): the code egresses exactly once at the
// documented boundary on each transport; every side channel is clean.

it('contains the invitation code to the single HTTP reveal', function (): void {
    /** @var TestResponse<Response> $response */
    $response = $this->assertNoSecretLeakageOfMinted(
        fn (): TestResponse => inviteOverHttp(['email' => 'sealed@example.test', 'ttl_seconds' => 3600]),
        fn (TestResponse $response): string => (string) $response->json('invitation_code'),
    );

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), (string) $response->json('invitation_code'));
});

it('contains the invitation code to the single CLI reveal', function (): void {
    $output = null;

    $this->assertNoSecretLeakageOfMinted(
        function () use (&$output): string {
            Artisan::call('bfc:invitation:issue', ['--email' => 'sealed-cli@example.test', '--ttl' => '3600', '--local' => true]);

            $output = Artisan::output();

            return $output;
        },
        function (string $output): ?string {
            return preg_match('/shown once: (\S+)/', $output, $matches) === 1 ? $matches[1] : null;
        },
    );

    preg_match('/shown once: (\S+)/', (string) $output, $matches);

    $this->assertRevealsSecretExactlyOnce((string) $output, $matches[1]);
});

it('gates the HTTP transport behind credential-admin authority', function (): void {
    $this->postJson('/bfc/invitations', ['email' => 'gate@example.test', 'ttl_seconds' => 3600])
        ->assertUnauthorized();

    $consume = ApiToken::query()->create([
        'name' => 'invite-consume',
        'token_hash' => hash('sha256', 'invite-consume-secret'),
        'abilities' => ['consume'],
    ]);

    $this->postJson('/bfc/invitations', ['email' => 'gate@example.test', 'ttl_seconds' => 3600], [
        'Authorization' => 'Bearer invite-consume-secret',
    ])->assertForbidden();

    expect($consume->exists)->toBeTrue()
        ->and(Invitation::query()->count())->toBe(0);
});

it('refuses the CLI transport without --local', function (): void {
    $exitCode = Artisan::call('bfc:invitation:issue', ['--email' => 'local@example.test', '--ttl' => '3600']);

    expect($exitCode)->toBe(Command::FAILURE)
        ->and(Artisan::output())->toContain('pass --local')
        ->and(Invitation::query()->count())->toBe(0);
});
