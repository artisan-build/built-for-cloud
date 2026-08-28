<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Actions\IssueInvitation;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ClaimError;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use ArtisanBuild\BuiltForCloud\IntegrationEntitlement;
use ArtisanBuild\BuiltForCloud\IntegrationEvent;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\InvitationOptions;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\Notifications\InvitationDeliveryNotification;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Console\Command;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use RuntimeException;
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
        'entitlement_version' => $eventOptions['version_override'] ?? $version,
        'external_subject' => $eventOptions['subject'] ?? 'sponsor-login',
    ]);
}

/**
 * The invitee's code, captured from the faked delivery notification — on
 * the integration path the response deliberately carries nothing.
 */
function capturedDeliveryCode(): string
{
    $code = null;

    Notification::assertSentOnDemand(
        InvitationDeliveryNotification::class,
        function (InvitationDeliveryNotification $notification) use (&$code): bool {
            $code = $notification->invitationCode;

            return true;
        },
    );

    return (string) $code;
}

/**
 * Every delivered code, in send order.
 *
 * @return list<string>
 */
function capturedDeliveryCodes(): array
{
    $codes = [];

    Notification::assertSentOnDemand(
        InvitationDeliveryNotification::class,
        function (InvitationDeliveryNotification $notification) use (&$codes): bool {
            $codes[] = $notification->invitationCode;

            return true;
        },
    );

    return $codes;
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

// PR8 locked AC 6: every pairwise ordering through the version gate. The
// integration path answers one uniform 202 acknowledgement, so every
// outcome is asserted through the database, and the invitee's code is
// captured from the delivery notification.

it('applies in-order versions and transactionally ignores an older one', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-1', 1)->assertStatus(202);
    inviteIntegrationEvent('evt-2', 2)->assertStatus(202);

    expect(Invitation::query()->count())->toBe(2)
        ->and(IntegrationEvent::query()->where('applied', true)->count())->toBe(2);

    // The delayed older event: acknowledged, ignored, nothing issued.
    inviteIntegrationEvent('evt-0', 1)->assertStatus(202);

    expect(Invitation::query()->count())->toBe(2)
        ->and(IntegrationEntitlement::query()->sole()->entitlement_version)->toBe(2)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-0')->sole()->applied)->toBeFalse();
});

it('supersedes the prior pending code when a newer event applies — a stolen older code dies', function (): void {
    Notification::fake();

    // The sponsor's email CHANGES between events, so only the (namespace,
    // subject) supersession — not the same-email one — can kill the v1
    // code.
    inviteIntegrationEvent('evt-v1', 1, ['email' => 'sponsor-old@example.test'])->assertStatus(202);

    $stolenCode = capturedDeliveryCode();

    inviteIntegrationEvent('evt-v2', 2, ['email' => 'sponsor-new@example.test'])->assertStatus(202);

    // The v1 code was superseded by the applying v2 event: it refuses
    // with the already-claimed class, and its used_by stays null —
    // supersession, not an acceptance.
    try {
        Invitation::accept($stolenCode, ['name' => 'Thief', 'password' => 'pw']);
        $this->fail('The superseded v1 code was accepted.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeAlreadyClaimed);
    }

    /** @var Invitation $superseded */
    $superseded = Invitation::query()->where('token', hash('sha256', $stolenCode))->sole();

    expect($superseded->used_by)->toBeNull()
        ->and(Invitation::query()->whereNull('accepted_at')->count())->toBe(1);
});

it('scopes integration supersession to its own namespace and subject — shared-email invitations survive', function (): void {
    Notification::fake();

    // A human invitation and two namespaces' invitations all share one
    // recipient address.
    $human = inviteOverHttp(['email' => 'shared@example.test', 'ttl_seconds' => 3600]);
    $human->assertCreated();

    inviteIntegrationEvent('evt-a1', 1, ['namespace' => 'ns-a', 'subject' => 'subj-a', 'email' => 'shared@example.test'])->assertStatus(202);
    inviteIntegrationEvent('evt-b1', 1, ['namespace' => 'ns-b', 'subject' => 'subj-b', 'email' => 'shared@example.test'])->assertStatus(202);

    // ns-b applies a NEWER event: only its own prior code may die — the
    // human invitation and ns-a's invitation stay alive despite the
    // shared email.
    inviteIntegrationEvent('evt-b2', 2, ['namespace' => 'ns-b', 'subject' => 'subj-b', 'email' => 'shared@example.test'])->assertStatus(202);

    $codes = capturedDeliveryCodes();

    expect($codes)->toHaveCount(3)
        ->and(Invitation::query()->whereNull('accepted_at')->count())->toBe(3);

    /** @var Invitation $superseded */
    $superseded = Invitation::query()->whereNotNull('accepted_at')->sole();

    // The one superseded row is ns-b's OWN prior code (evt-b1's), marked
    // as supersession, not acceptance.
    expect($superseded->getAttributes()['token'])->toBe(hash('sha256', $codes[1]))
        ->and($superseded->used_by)->toBeNull();

    // ns-a's code is still pending, and the human invitation still
    // accepts (one acceptance only — both are addressed to the same
    // email, and users.email is unique).
    expect(
        Invitation::query()->where('token', hash('sha256', $codes[0]))->whereNull('accepted_at')->exists(),
    )->toBeTrue();

    $user = Invitation::accept((string) $human->json('invitation_code'), ['name' => 'Human Invitee', 'password' => 'pw']);

    expect($user->getAttribute('email'))->toBe('shared@example.test');
});

it('ignores an out-of-order older version arriving first-reversed', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-new', 5)->assertStatus(202);
    inviteIntegrationEvent('evt-old', 3)->assertStatus(202);

    expect(Invitation::query()->count())->toBe(1)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-old')->sole()->applied)->toBeFalse()
        ->and(IntegrationEntitlement::query()->sole()->entitlement_version)->toBe(5);
});

it('ignores an equal version under a fresh event id — not newer is not applied', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-a', 4)->assertStatus(202);
    inviteIntegrationEvent('evt-b', 4)->assertStatus(202);

    expect(Invitation::query()->count())->toBe(1)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-b')->sole()->applied)->toBeFalse();
});

it('replays a duplicate event id idempotently — byte-identical response, no second invitation', function (): void {
    Notification::fake();

    $original = inviteIntegrationEvent('evt-dup', 1);
    $replay = inviteIntegrationEvent('evt-dup', 1);

    $original->assertStatus(202);
    $replay->assertStatus(202);

    expect((string) $replay->getContent())->toBe((string) $original->getContent())
        ->and(Invitation::query()->count())->toBe(1)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-dup')->count())->toBe(1);
});

it('does not resurrect an accepted invitation when its event replays', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-accept', 1)->assertStatus(202);

    Invitation::accept(capturedDeliveryCode(), ['name' => 'Sponsor', 'password' => 'pw']);

    inviteIntegrationEvent('evt-accept', 1)->assertStatus(202);

    expect(Invitation::query()->count())->toBe(1)
        ->and(Invitation::query()->sole()->accepted_at)->not->toBeNull()
        ->and(Invitation::query()->sole()->used_by)->not->toBeNull();
});

// PR8 rework Fix 1: the gate is race-safe on first contact — a concurrent
// winner's committed row turns the loser's unique violation into the
// ordinary re-decided acknowledgement, never a naked 500. The competitor
// is injected between the check and the create via DB::listen; its write
// shares this test's single connection, so the first attempt's rollback
// takes it too and the retry decides against a clean slate — the rescue
// path itself is what these tests force to execute (without the catch,
// the request 500s).

it('rescues a racing first entitlement create into the documented acknowledgement', function (): void {
    Notification::fake();

    $competitorFired = false;

    DB::listen(function (QueryExecuted $query) use (&$competitorFired): void {
        if (! $competitorFired
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'integration_entitlements')) {
            $competitorFired = true;

            DB::table('integration_entitlements')->insert([
                'id' => (string) Str::uuid(),
                'integration_namespace' => 'github-sponsors',
                'external_subject' => 'sponsor-login',
                'entitlement_version' => 5,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    });

    inviteIntegrationEvent('evt-race-first', 3)->assertStatus(202);

    expect($competitorFired)->toBeTrue()
        ->and(IntegrationEntitlement::query()->count())->toBe(1)
        ->and(IntegrationEvent::query()->where('event_id', 'evt-race-first')->count())->toBe(1)
        ->and(Invitation::query()->count())->toBeLessThanOrEqual(1);
});

it('rescues a racing duplicate event id into the documented acknowledgement', function (): void {
    Notification::fake();

    // The subject already has an entitlement so the collision lands on
    // the EVENT table's unique (namespace, event_id) index.
    IntegrationEntitlement::query()->create([
        'integration_namespace' => 'github-sponsors',
        'external_subject' => 'sponsor-login',
        'entitlement_version' => 1,
    ]);

    $competitorFired = false;

    DB::listen(function (QueryExecuted $query) use (&$competitorFired): void {
        if (! $competitorFired
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'integration_events')) {
            $competitorFired = true;

            DB::table('integration_events')->insert([
                'id' => (string) Str::uuid(),
                'integration_namespace' => 'github-sponsors',
                'event_id' => 'evt-race-dup',
                'external_subject' => 'sponsor-login',
                'event_kind' => 'invite',
                'entitlement_version' => 2,
                'applied' => true,
                'invitation_id' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    });

    inviteIntegrationEvent('evt-race-dup', 2)->assertStatus(202);

    expect($competitorFired)->toBeTrue()
        ->and(IntegrationEvent::query()->where('event_id', 'evt-race-dup')->count())->toBe(1)
        ->and(Invitation::query()->count())->toBeLessThanOrEqual(1);
});

it('survives losing both gate races in one request — the third attempt decides', function (): void {
    Notification::fake();

    // Attempt 1 loses the ENTITLEMENT-row race; attempt 2 loses the
    // EVENT-id race; attempt 3 runs clean and applies. (Each injected
    // competitor shares this test's single connection, so it rolls back
    // with the attempt it sabotaged — which is exactly what leaves the
    // next attempt a clean slate to decide on.)
    $entitlementInjected = false;
    $eventInjected = false;

    DB::listen(function (QueryExecuted $query) use (&$entitlementInjected, &$eventInjected): void {
        if (preg_match('/^\s*select\b/i', $query->sql) !== 1) {
            return;
        }

        if (! $entitlementInjected && str_contains($query->sql, 'integration_entitlements')) {
            $entitlementInjected = true;

            DB::table('integration_entitlements')->insert([
                'id' => (string) Str::uuid(),
                'integration_namespace' => 'github-sponsors',
                'external_subject' => 'sponsor-login',
                'entitlement_version' => 9,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            return;
        }

        if ($entitlementInjected && ! $eventInjected && str_contains($query->sql, 'integration_events')) {
            $eventInjected = true;

            DB::table('integration_events')->insert([
                'id' => (string) Str::uuid(),
                'integration_namespace' => 'github-sponsors',
                'event_id' => 'evt-double-loss',
                'external_subject' => 'sponsor-login',
                'event_kind' => 'invite',
                'entitlement_version' => 3,
                'applied' => true,
                'invitation_id' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    });

    inviteIntegrationEvent('evt-double-loss', 3)->assertStatus(202);

    expect($entitlementInjected)->toBeTrue()
        ->and($eventInjected)->toBeTrue()
        ->and(IntegrationEvent::query()->where('event_id', 'evt-double-loss')->count())->toBe(1)
        ->and(IntegrationEntitlement::query()->count())->toBe(1)
        ->and(Invitation::query()->count())->toBe(1);
});

it('escapes cleanly after the contention bound with no partial state', function (): void {
    Notification::fake();

    // EVERY attempt loses the entitlement race: past the bound the verb
    // answers a clean, secret-free server error, and no attempt left
    // anything behind.
    $collisions = 0;

    DB::listen(function (QueryExecuted $query) use (&$collisions): void {
        if (preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'integration_entitlements')) {
            $collisions++;

            DB::table('integration_entitlements')->insert([
                'id' => (string) Str::uuid(),
                'integration_namespace' => 'github-sponsors',
                'external_subject' => 'sponsor-login',
                'entitlement_version' => 9,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }
    });

    $response = inviteIntegrationEvent('evt-doomed', 3);

    $response->assertStatus(500);

    expect((string) $response->json('message'))->toContain('safe to retry')
        ->and((string) $response->getContent())->not->toContain('SQL')
        ->and($collisions)->toBe(3)
        ->and(IntegrationEntitlement::query()->count())->toBe(0)
        ->and(IntegrationEvent::query()->count())->toBe(0)
        ->and(Invitation::query()->count())->toBe(0);
});

// PR8 rework Fix 2: entitlement versions are bounded to [1, 2^53] — an
// oversize digit string that would saturate integer parsing is rejected,
// never accepted, so a poisoned maximum can never freeze a subject.

it('rejects an oversize entitlement version identically on both transports', function (): void {
    $http = inviteIntegrationEvent('evt-huge', 1, ['version_override' => '99999999999999999999']);

    $http->assertStatus(422);

    $cliExit = Artisan::call('bfc:invitation:issue', [
        '--email' => 'sponsor@example.test',
        '--ttl' => '3600',
        '--integration-namespace' => 'github-sponsors',
        '--event-id' => 'evt-huge',
        '--entitlement-version' => '99999999999999999999',
        '--external-subject' => 'sponsor-login',
        '--local' => true,
    ]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe((string) $http->json('message'))
        ->and(IntegrationEntitlement::query()->count())->toBe(0)
        ->and(Invitation::query()->count())->toBe(0);
});

it('accepts the 2^53 boundary and rejects everything past or below the range', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-max', 9007199254740992)->assertStatus(202);

    expect(IntegrationEntitlement::query()->sole()->entitlement_version)->toBe(9007199254740992);

    inviteIntegrationEvent('evt-past-max', 9007199254740993)->assertStatus(422);
    inviteIntegrationEvent('evt-zero', 0)->assertStatus(422);
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

// Fold: length validation at the shared boundary — each free-text field
// is bounded to its column, with the same 422 on both transports.

it('rejects oversize free-text fields at the shared boundary', function (): void {
    $base = ['email' => 'long@example.test', 'ttl_seconds' => 3600];

    $oversize = [
        'invited_by' => str_repeat('a', 65),
        'role' => str_repeat('r', 256),
        'integration_namespace' => str_repeat('n', 256),
        'event_id' => str_repeat('e', 256),
        'external_subject' => str_repeat('s', 256),
    ];

    foreach ($oversize as $field => $value) {
        $response = inviteOverHttp($base + [$field => $value]);

        $response->assertStatus(422);

        expect((string) $response->json('message'))->toContain($field);
    }

    // CLI parity on one representative field: same message verbatim.
    $http = inviteOverHttp($base + ['invited_by' => str_repeat('a', 65)]);

    $cliExit = Artisan::call('bfc:invitation:issue', [
        '--email' => 'long@example.test',
        '--ttl' => '3600',
        '--invited-by' => str_repeat('a', 65),
        '--local' => true,
    ]);

    expect($cliExit)->toBe(Command::FAILURE)
        ->and(trim(Artisan::output()))->toBe((string) $http->json('message'))
        ->and(Invitation::query()->count())->toBe(0);
});

// PR8 locked AC 7: the non-enumerating shape — exact same keys and status
// for a fresh subject, an already-invited one, and an already-accepted one.

it('answers with one shape whatever the prior state of the invited human', function (): void {
    $fresh = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);
    $reinvited = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);

    // The re-invite superseded the fresh code, so the LIVE code is the
    // re-invited one.
    Invitation::accept((string) $reinvited->json('invitation_code'), ['name' => 'Probe', 'password' => 'pw']);

    $afterAccept = inviteOverHttp(['email' => 'probe@example.test', 'ttl_seconds' => 3600]);

    foreach ([$fresh, $reinvited, $afterAccept] as $response) {
        $response->assertCreated();

        expect(array_keys((array) $response->json()))->toBe(['invitation_id', 'invitation_code', 'email']);
    }
});

it('answers byte-identically for fresh, ignored and replayed integration events', function (): void {
    Notification::fake();

    $applied = inviteIntegrationEvent('evt-shape-1', 2);
    $ignored = inviteIntegrationEvent('evt-shape-0', 1);
    $replayed = inviteIntegrationEvent('evt-shape-1', 2);

    foreach ([$applied, $ignored, $replayed] as $response) {
        $response->assertStatus(202);

        expect((string) $response->getContent())->toBe((string) $applied->getContent());
    }
});

// PR8 rework Fix 3: supersession on the human path — an issuer replaces a
// code by issuing again; the old link is dead, the new one works.

it('supersedes the prior pending invitation when the same email is re-invited', function (): void {
    $first = inviteOverHttp(['email' => 'replace@example.test', 'ttl_seconds' => 3600]);
    $second = inviteOverHttp(['email' => 'replace@example.test', 'ttl_seconds' => 3600]);

    try {
        Invitation::accept((string) $first->json('invitation_code'), ['name' => 'Old Link', 'password' => 'pw']);
        $this->fail('The superseded first code was accepted.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeAlreadyClaimed);
    }

    $user = Invitation::accept((string) $second->json('invitation_code'), ['name' => 'New Link', 'password' => 'pw']);

    expect($user->getAttribute('email'))->toBe('replace@example.test')
        ->and(Invitation::query()->whereNotNull('used_by')->count())->toBe(1);
});

it('leaves a completed acceptance intact when a supersede races it — the conditional update matches nothing', function (): void {
    $first = inviteOverHttp(['email' => 'settled@example.test', 'ttl_seconds' => 3600]);

    $user = Invitation::accept((string) $first->json('invitation_code'), ['name' => 'Settled', 'password' => 'pw']);

    // The accept won before the re-invite's supersede ran: the conditional
    // whereNull(accepted_at) matches zero rows, the acceptance (used_by
    // included) is untouched, and the new invitation still issues.
    $second = inviteOverHttp(['email' => 'settled@example.test', 'ttl_seconds' => 3600]);

    $second->assertCreated();

    /** @var Invitation $acceptedRow */
    $acceptedRow = Invitation::query()->whereNotNull('used_by')->sole();

    expect($acceptedRow->used_by)->toBe((string) $user->getKey())
        ->and(Invitation::query()->whereNull('accepted_at')->count())->toBe(1);
});

// PR8 rework Fix 5 (delivery): the instance delivers on the integration
// path — an addressed applying event mails the invitee a working code;
// ignored events and unaddressed events mail nobody.

it('delivers the invitation code to the addressed invitee when an integration event applies', function (): void {
    Notification::fake();

    $response = inviteIntegrationEvent('evt-deliver', 1, ['email' => 'invitee@example.test']);

    $response->assertStatus(202);

    $code = capturedDeliveryCode();

    Notification::assertSentOnDemand(
        InvitationDeliveryNotification::class,
        fn (InvitationDeliveryNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => ($notifiable->routes['mail'] ?? null) === 'invitee@example.test',
    );

    // The response carries no code; the store carries only the hash; the
    // delivered code actually works.
    expect((string) $response->getContent())->not->toContain($code)
        ->and(Invitation::query()->where('token', hash('sha256', $code))->exists())->toBeTrue();

    $user = Invitation::accept($code, ['name' => 'Invitee', 'password' => 'pw']);

    expect($user->getAttribute('email'))->toBe('invitee@example.test');
});

it('delivers nothing for an ignored event or an unaddressed applying event', function (): void {
    Notification::fake();

    inviteIntegrationEvent('evt-noship-1', 5)->assertStatus(202);

    Notification::assertSentOnDemandTimes(InvitationDeliveryNotification::class, 1);

    // Ignored (older) event: acknowledged, nothing delivered.
    inviteIntegrationEvent('evt-noship-0', 4)->assertStatus(202);

    Notification::assertSentOnDemandTimes(InvitationDeliveryNotification::class, 1);

    // Unaddressed applying event: acknowledged, the invitation exists,
    // and nobody is mailed — deliver via an addressed human invite, which
    // supersedes it.
    inviteIntegrationEvent('evt-open', 6, ['email' => '', 'subject' => 'open-subject'])->assertStatus(202);

    Notification::assertSentOnDemandTimes(InvitationDeliveryNotification::class, 1);

    expect(Invitation::query()->whereNull('email')->count())->toBe(1);
});

// Judge fold (AC 8): the issued audit row, its outbox row and the
// invitation are ONE transaction — a failure after the recorder call
// rolls all three back together (the PR4 sabotage pattern).

it('rolls the invitation, audit row and outbox row back together when the issue transaction dies late', function (): void {
    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*insert\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credential_outbox')) {
            $armed = false;

            throw new RuntimeException('simulated process death after the outbox write');
        }
    });

    $issue = app(IssueInvitation::class);

    expect(fn (): mixed => $issue(InvitationOptions::fromInput([
        'email' => 'doomed@example.test',
        'ttl_seconds' => 3600,
    ])))->toThrow(RuntimeException::class);

    expect(Invitation::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0)
        ->and(CredentialOutboxEntry::query()->count())->toBe(0);
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
