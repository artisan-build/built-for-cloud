<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionClient;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** @return array{0: User, 1: ManagedTransitionAuthorityFixture} */
function p4bConfigure(ManagedTransitionDirection $direction = ManagedTransitionDirection::Adopt): array
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => $direction->modeBefore()->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_base_url' => 'https://transition-authority.example.test',
    ]);
    config([
        'built-for-cloud.managed.client_secret' => 'transition-secret',
        'built-for-cloud.managed.ca_bundle' => null,
    ]);
    $owner = User::query()->create([
        'name' => 'Transition Owner',
        'email' => 'transition-owner@example.test',
    ]);
    $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();
    $fixture = new ManagedTransitionAuthorityFixture;
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    return [$owner->refresh(), $fixture];
}

function p4bPrepared(
    ?ManagedTransitionAuthorityFixture &$fixture = null,
    ManagedTransitionDirection $direction = ManagedTransitionDirection::Adopt,
): ManagedTransition {
    [$owner, $configured] = p4bConfigure($direction);
    $fixture = $configured;

    return app(ManagedTransitions::class)->prepare($owner, $direction);
}

function p4bProposed(?ManagedTransitionAuthorityFixture &$fixture = null): ManagedTransition
{
    $transition = p4bPrepared($fixture);
    $transition = app(ManagedTransitions::class)->fetchRoster($transition);
    $owner = User::query()->whereNotNull('owner_slot')->sole();

    return app(ManagedTransitions::class)->propose($transition, [
        [
            'scalpels_id' => 'direct-member',
            'local_kind' => null,
            'local_id' => null,
            'role' => 'member',
            'disposition' => 'create',
            'final_email' => 'created-direct-member@example.test',
        ],
        [
            'scalpels_id' => null,
            'local_kind' => 'user',
            'local_id' => (string) $owner->getKey(),
            'role' => null,
            'disposition' => 'exclude',
            'final_email' => null,
        ],
    ]);
}

function p4bCommitted(?ManagedTransitionAuthorityFixture &$fixture = null): ManagedTransition
{
    $transition = app(ManagedTransitions::class)->stage(p4bProposed($fixture));

    return app(ManagedTransitions::class)->commit($transition, static function (): void {
        if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed) === null) {
            throw new RuntimeException('Fixture failed to switch authority mode.');
        }
    });
}

function p4bOwnerRequest(User $owner, ?int $sessionVersion = null): Request
{
    $request = Request::create('/bfc/managed-transition/abandon', 'POST');
    $session = app('session')->driver();
    $session->start();
    $session->put(StandaloneAccess::SESSION_VERSION_KEY, $sessionVersion ?? $owner->auth_session_version);
    $request->setLaravelSession($session);
    $request->setUserResolver(static fn (): User => $owner);

    return $request;
}

function p4bClient(ManagedTransition $transition, ?Factory $http = null): ManagedTransitionClient
{
    return new ManagedTransitionClient($http ?? app(Factory::class), $transition);
}

/** @return array<string, mixed> */
function p4bProtectedState(): array
{
    return [
        'users' => DB::table('users')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'authority' => (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first(),
        'transition' => DB::table('bfc_managed_transitions')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'roster' => DB::table('bfc_managed_transition_roster_members')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'cursors' => DB::table('bfc_managed_transition_roster_cursors')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'mappings' => DB::table('bfc_managed_transition_mappings')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'invitations' => DB::table('invitations')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'sessions' => DB::table('sessions')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'password_resets' => DB::table('password_reset_tokens')->orderBy('email')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'api_tokens' => DB::table('api_tokens')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
        'credentials' => DB::table('credentials')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all(),
    ];
}

it('runs T1 through T4 with exact persisted keyed bytes and the durable state machine', function (): void {
    $transition = p4bProposed($fixture);
    $transition = app(ManagedTransitions::class)->stage($transition);
    $transition = app(ManagedTransitions::class)->commit($transition, static function (ManagedTransition $locked): void {
        expect($locked->status)->toBe(ManagedTransitionStatus::Staged);
        if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed) === null) {
            throw new RuntimeException('Fixture failed to switch authority mode.');
        }
    });
    $transition = app(ManagedTransitions::class)->acknowledge($transition);

    expect($transition->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($transition->authority_acknowledged_at)->toBe('2026-09-11T12:05:00+00:00')
        ->and($transition->local_commit_receipt)->toBeString()->not->toBeEmpty()
        ->and($fixture->executionCounts)->toMatchArray(['T1' => 1, 'T2' => 1, 'T3' => 1, 'T4' => 1]);

    foreach (['T1' => 'prepare', 'T3' => 'stage', 'T4' => 'ack'] as $leg => $prefix) {
        $call = collect($fixture->calls)->firstWhere('leg', $leg);
        expect($call)->not->toBeNull()
            ->and($call['body'])->toBe($transition->getAttribute($prefix.'_request_body'))
            ->and($call['digest'])->toBe(hash('sha256', $call['body']))
            ->and($call['digest'])->toBe($transition->getAttribute($prefix.'_body_digest'));
    }
});

it('recovers an outcome-unknown T1 through T6 and replays one authority execution', function (): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->crashAfterExecution = 'T1';

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    $firstBody = collect($fixture->calls)->firstWhere('leg', 'T1')['body'];
    $requestId = $attempt->transition_request_id;

    $recovered = app(ManagedTransitions::class)->recover($attempt);
    $t1Bodies = collect($fixture->calls)->where('leg', 'T1')->pluck('body')->all();
    $t1Keys = collect($t1Bodies)->map(
        static fn (string $body): string => json_decode($body, true, flags: JSON_THROW_ON_ERROR)['transition_request_id'],
    )->all();

    expect($recovered->status)->toBe(ManagedTransitionStatus::Prepared)
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T6', 'T1'])
        ->and($t1Bodies)->toBe([$firstBody, $firstBody])
        ->and($t1Keys)->toBe([$requestId, $requestId])
        ->and($recovered->transition_request_id)->toBe($requestId)
        ->and($fixture->executionCounts['T1'])->toBe(1)
        ->and($recovered->transition_id)->toBe('authority-transition-1');
});

it('uses T6 status and transition identity before accepting a T1 recovery replay', function (string $case): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->crashAfterExecution = 'T1';
    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    $fixture->transform = static function (string $leg, array $payload) use ($case): array {
        if ($leg !== 'T6') {
            return $payload;
        }

        if ($case === 'terminal status') {
            $payload['status'] = 'acknowledged';
            $payload['authority_generation'] = 8;
        } elseif ($case === 'invalid status') {
            $payload['status'] = 'unknown';
        } else {
            $payload['transition_id'] = 'crossed-transition';
        }

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->recover($attempt))
        ->toThrow(ManagedAuthRefused::class)
        ->and($attempt->fresh()->status)->toBe(ManagedTransitionStatus::Preparing)
        ->and(collect($fixture->calls)->pluck('leg')->all())
        ->toBe(in_array($case, ['terminal status', 'invalid status'], true) ? ['T1', 'T6'] : ['T1', 'T6', 'T1']);
})->with(['terminal status', 'invalid status', 'crossed transition']);

it('preserves a preparing attempt when its recorded T1 response is durably refused', function (): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->transform = static function (string $leg, array $payload): array {
        if ($leg === 'T1') {
            $payload['status'] = 'invalid';
        }

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();

    expect(fn () => app(ManagedTransitions::class)->recover($attempt))
        ->toThrow(ManagedAuthRefused::class)
        ->and($attempt->fresh()->status)->toBe(ManagedTransitionStatus::Preparing)
        ->and(fn () => app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class, 'transition_in_progress')
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T6', 'T1'])
        ->and(collect($fixture->calls)->where('leg', 'T7'))->toHaveCount(0);
});

it('preserves a preparing attempt when a prepared T1 replay has a retryable or invalid response', function (
    string $case,
    ?int $retryAfter,
): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->crashAfterExecution = 'T1';

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    $http = new Factory;
    $http->fake(static function (ClientRequest $request) use ($case, $fixture): mixed {
        $response = $fixture->respond($request);
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        if ($path !== '/managed-transition/v1/transitions') {
            return $response;
        }

        return match ($case) {
            '503' => Http::response([
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'error' => 'server_error',
            ], 503, ['Retry-After' => '120']),
            '429' => Http::response([
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'error' => 'rate_limited',
            ], 429, ['Retry-After' => '30']),
            'malformed body' => Http::response('not json'),
            'binding failure' => Http::response([
                ...$response->json(),
                'installation_id' => 'crossed-installation',
            ]),
        };
    });

    $refusal = null;
    try {
        (new ManagedTransitions($http))->recover($attempt);
    } catch (ManagedAuthRefused $exception) {
        $refusal = $exception;
    }

    expect($refusal)->toBeInstanceOf(ManagedAuthRefused::class)
        ->and($refusal?->retryAfterSeconds)->toBe($retryAfter)
        ->and($attempt->fresh()->status)->toBe(ManagedTransitionStatus::Preparing)
        ->and(ManagedTransition::query()->whereNotIn('status', [
            ManagedTransitionStatus::Acknowledged->value,
            ManagedTransitionStatus::Abandoned->value,
        ])->count())->toBe(1)
        ->and(fn () => app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class, 'transition_in_progress')
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T6', 'T1'])
        ->and(collect($fixture->calls)->where('leg', 'T7'))->toHaveCount(0);
})->with([
    '503 with Retry-After' => ['503', 120],
    '429 with Retry-After' => ['429', 30],
    'malformed body' => ['malformed body', null],
    'binding failure' => ['binding failure', null],
]);

it('locally discards a preparing attempt when T6 reports no transition', function (): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->crashBeforeExecution = 'T1';

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    $discarded = app(ManagedTransitions::class)->recover($attempt);
    expect($discarded->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and(ManagedTransition::query()->whereNotIn('status', [
            ManagedTransitionStatus::Acknowledged->value,
            ManagedTransitionStatus::Abandoned->value,
        ])->count())->toBe(0);
    $replacement = app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);

    expect($discarded->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and($discarded->transition_id)->toBeNull()
        ->and($replacement->id)->not->toBe($discarded->id)
        ->and($replacement->status)->toBe(ManagedTransitionStatus::Prepared)
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T6', 'T1'])
        ->and(collect($fixture->calls)->where('leg', 'T7'))->toHaveCount(0);
});

it('locally converges a preparing attempt when T6 reports an abandoned transition', function (): void {
    $transition = p4bPrepared($fixture);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $key = str_repeat('a', 43);
    $body = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $key,
        'abandon_request_body' => $body,
        'abandon_body_digest' => hash('sha256', $body),
    ])->save();
    p4bClient($transition->fresh())->abandon();
    $transition->forceFill(['status' => ManagedTransitionStatus::Preparing])->save();

    $discarded = app(ManagedTransitions::class)->recover($transition->fresh());
    $replacement = app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);

    expect($discarded->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and($replacement->id)->not->toBe($discarded->id)
        ->and($replacement->status)->toBe(ManagedTransitionStatus::Prepared)
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T7', 'T6', 'T1'])
        ->and(collect($fixture->calls)->where('leg', 'T7'))->toHaveCount(1);
});

it('recovers outcome-unknown stage and ack from T5 without blind mutation replay', function (string $leg): void {
    $transition = p4bProposed($fixture);
    $fixture->crashAfterExecution = $leg;

    if ($leg === 'T3') {
        expect(fn () => app(ManagedTransitions::class)->stage($transition))->toThrow(ManagedAuthRefused::class);
        $attempt = ManagedTransition::query()->sole();
        expect($attempt->status)->toBe(ManagedTransitionStatus::Staging);
        $recovered = app(ManagedTransitions::class)->recover($attempt);
        expect($recovered->status)->toBe(ManagedTransitionStatus::Staged)
            ->and($fixture->executionCounts['T3'])->toBe(1);

        return;
    }

    $transition = app(ManagedTransitions::class)->stage($transition);
    $transition = app(ManagedTransitions::class)->commit($transition, static function (): void {
        if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed) === null) {
            throw new RuntimeException('Fixture failed to switch authority mode.');
        }
    });
    expect(fn () => app(ManagedTransitions::class)->acknowledge($transition))->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    expect($attempt->status)->toBe(ManagedTransitionStatus::Acknowledging);
    $recovered = app(ManagedTransitions::class)->recover($attempt);
    expect($recovered->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($fixture->executionCounts['T4'])->toBe(1);
})->with(['T3', 'T4']);

it('persists a complete bounded roster without treating T2 as membership state', function (): void {
    $transition = p4bPrepared($fixture);
    $member = User::query()->create(['name' => 'Existing Member', 'email' => 'existing@example.test']);
    $member->forceFill([
        'role' => 'admin',
        'status' => 'active',
        'managed_membership_generation' => 6,
        'managed_membership_roster_version' => 39,
        'managed_membership_response_sequence' => 70,
        'managed_membership_responded_at' => '2026-09-10T00:00:00+00:00',
        'membership_confirmed_at' => now()->subDay(),
        'membership_checked_at' => now()->subDay(),
        'membership_response_at' => now()->subDay(),
        'scalpels_issuer' => $transition->issuer,
        'scalpels_connection_id' => $transition->connection_id,
        'scalpels_id' => 'direct-member',
    ])->save();
    $beforeUser = $member->fresh()->getAttributes();
    $beforeAuthority = (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();

    $rostered = app(ManagedTransitions::class)->fetchRoster($transition);

    expect($rostered->status)->toBe(ManagedTransitionStatus::Rostered)
        ->and($rostered->roster_members_received)->toBe(1)
        ->and(DB::table('bfc_managed_transition_roster_members')->value('scalpels_id'))->toBe('direct-member')
        ->and($member->fresh()->getAttributes())->toBe($beforeUser)
        ->and((array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first())->toBe($beforeAuthority);
});

it('refuses incomplete or malformed roster snapshots as a whole and preserves an absent local member', function (string $case): void {
    $transition = p4bPrepared($fixture);
    $missing = User::query()->create(['name' => 'Absent From Page', 'email' => 'absent-page@example.test']);
    $missing->forceFill([
        'role' => 'admin',
        'status' => 'active',
        'scalpels_issuer' => $transition->issuer,
        'scalpels_connection_id' => $transition->connection_id,
        'scalpels_id' => 'direct-member',
    ])->save();

    if ($case === 'duplicate subject') {
        $fixture->rosterPages = [
            'NULL' => [$fixture->rosterPages['NULL'][0]],
            'cursor-two' => [$fixture->rosterPages['NULL'][0]],
        ];
        $transition->forceFill(['roster_total' => 2])->save();
    } elseif ($case === 'cyclic cursor') {
        $fixture->rosterPages = ['NULL' => [], 'cursor-two' => []];
        $transition->forceFill(['roster_total' => 0])->save();
        $fixture->transform = static function (string $leg, array $payload): array {
            if ($leg === 'T2' && ($payload['next_cursor'] ?? null) === null) {
                $payload['next_cursor'] = 'cursor-two';
            }

            return $payload;
        };
    } else {
        $fixture->transform = static function (string $leg, array $payload) use ($case): array {
            if ($leg !== 'T2') {
                return $payload;
            }

            match ($case) {
                'version shift' => $payload['roster_version'] = 42,
                'cutoff mismatch' => $payload['roster_cutoff_at'] = '2026-09-11T12:00:01+00:00',
                'page count mismatch' => $payload['page_total'] = 0,
                'truncated distinct count' => [$payload['members'], $payload['page_total']] = [[], 0],
                'page total bound' => $payload['page_total'] = 501,
                default => null,
            };

            return $payload;
        };
    }

    expect(fn () => app(ManagedTransitions::class)->fetchRoster($transition))->toThrow(ManagedAuthRefused::class)
        ->and(DB::table('bfc_managed_transition_roster_members')->count())->toBe(0)
        ->and(DB::table('bfc_managed_transition_roster_cursors')->count())->toBe(0)
        ->and($missing->fresh()->status)->toBe('active')
        ->and($missing->fresh()->role)->toBe('admin')
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Prepared);
    if ($case === 'cyclic cursor') {
        expect(collect($fixture->calls)->where('leg', 'T2'))->toHaveCount(2);
    }
})->with([
    'version shift',
    'cutoff mismatch',
    'page count mismatch',
    'truncated distinct count',
    'duplicate subject',
    'cyclic cursor',
    'page total bound',
]);

it('enforces the roster page and response-size bounds', function (string $case): void {
    $transition = p4bPrepared($fixture);

    if ($case === 'members per page') {
        $fixture->rosterPages = ['NULL' => []];
        foreach (range(1, 501) as $number) {
            $fixture->rosterPages['NULL'][] = [
                ...((new ManagedTransitionAuthorityFixture)->rosterPages['NULL'][0]),
                'scalpels_id' => 'member-'.$number,
                'contact_email' => 'member-'.$number.'@example.test',
            ];
        }
        $transition->forceFill(['roster_total' => 501])->save();
    } elseif ($case === 'response bytes') {
        $fixture->transform = static function (string $leg, array $payload): array {
            if ($leg === 'T2') {
                $payload['ignored_extension'] = str_repeat('x', 1_048_576);
            }

            return $payload;
        };
    } else {
        $fixture->rosterPages = ['NULL' => []];
        foreach (range(1, 200) as $number) {
            $key = $number === 1 ? 'NULL' : 'cursor-'.$number;
            $fixture->rosterPages[$key] = [[
                ...((new ManagedTransitionAuthorityFixture)->rosterPages['NULL'][0]),
                'scalpels_id' => 'member-'.$number,
                'contact_email' => 'member-'.$number.'@example.test',
            ]];
        }
        $fixture->rosterPages['cursor-201'] = [[
            ...((new ManagedTransitionAuthorityFixture)->rosterPages['NULL'][0]),
            'scalpels_id' => 'member-201',
            'contact_email' => 'member-201@example.test',
        ]];
        $transition->forceFill(['roster_total' => 201])->save();
    }

    expect(fn () => app(ManagedTransitions::class)->fetchRoster($transition))->toThrow(ManagedAuthRefused::class)
        ->and(DB::table('bfc_managed_transition_roster_members')->count())->toBe(0);
})->with(['members per page', 'response bytes', 'pages']);

it('derives the transmitted roster from direct memberships and excludes agency-only access', function (): void {
    $transition = p4bPrepared($fixture);
    $rostered = app(ManagedTransitions::class)->fetchRoster($transition);
    $sourceIds = collect($fixture->rosterSources)->pluck('member.scalpels_id')->all();
    $transmittedIds = DB::table('bfc_managed_transition_roster_members')->pluck('scalpels_id')->all();

    expect($sourceIds)->toContain('direct-member', 'agency-only-member')
        ->and($transmittedIds)->toBe(['direct-member'])
        ->and($rostered->roster_members_received)->toBe(1);
});

it('ignores well-typed unknown top-level and member response fields', function (): void {
    $transition = p4bPrepared($fixture);
    $fixture->transform = static function (string $leg, array $payload): array {
        if ($leg === 'T2') {
            $payload['future_top_level_field'] = ['version' => 2];
            $payload['members'][0]['future_member_field'] = 'supported-later';
        }

        return $payload;
    };

    expect(app(ManagedTransitions::class)->fetchRoster($transition)->status)
        ->toBe(ManagedTransitionStatus::Rostered)
        ->and(DB::table('bfc_managed_transition_roster_members')->value('scalpels_id'))
        ->toBe('direct-member');
});

it('refuses a changed immutable cutoff reported by T5 during recovery', function (): void {
    $transition = p4bPrepared($fixture);
    $fixture->transform = static function (string $leg, array $payload): array {
        if ($leg === 'T5') {
            $payload['roster_cutoff_at'] = '2026-09-11T12:00:02+00:00';
        }

        return $payload;
    };
    $before = p4bProtectedState();

    expect(fn () => app(ManagedTransitions::class)->recover($transition))
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4bProtectedState())->toBe($before);
});

it('refuses unsafe authority member strings before roster persistence', function (string $field, mixed $value): void {
    $transition = p4bPrepared($fixture);
    $fixture->rosterPages['NULL'][0][$field] = $value;

    expect(fn () => app(ManagedTransitions::class)->fetchRoster($transition))->toThrow(ManagedAuthRefused::class)
        ->and(DB::table('bfc_managed_transition_roster_members')->count())->toBe(0);
})->with([
    'invalid contact email' => ['contact_email', "not\nan-address"],
    'overlong contact email' => ['contact_email', str_repeat('a', 245).'@example.test'],
    'overlong display name' => ['display_name', str_repeat('n', 256)],
    'verified arbitrary bytes' => ['contact_email', "bad\0@example.test"],
]);

it('refuses each frozen T1 binding mismatch before associating an authority transition', function (string $field, mixed $value): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->transform = static function (string $leg, array $payload) use ($field, $value): array {
        if ($leg === 'T1') {
            $payload[$field] = $value;
        }

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $attempt = ManagedTransition::query()->sole();
    expect($attempt->status)->toBe(ManagedTransitionStatus::Preparing)
        ->and($attempt->transition_id)->toBeNull();
})->with([
    'contract' => ['contract_version', 'managed-transition-v2'],
    'issuer' => ['issuer', 'https://other-issuer.example.test'],
    'connection' => ['connection_id', 'other-connection'],
    'organization' => ['organization_id', 'other-organization'],
    'installation' => ['installation_id', 'other-installation'],
    'generation' => ['authority_generation', 8],
    'transition request' => ['transition_request_id', 'other-request'],
    'direction' => ['direction', 'exit'],
]);

it('refuses a T1 response crossed from another same-installation request', function (): void {
    $first = p4bPrepared($fixture);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    app(ManagedTransitions::class)->abandon(p4bOwnerRequest($owner), $first);
    $firstRequestId = $first->transition_request_id;
    $fixture->transform = static function (string $leg, array $payload) use ($firstRequestId): array {
        if ($leg === 'T1') {
            $payload['transition_request_id'] = $firstRequestId;
        }

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $second = ManagedTransition::query()
        ->where('id', '!=', $first->id)
        ->sole();

    expect($second->transition_request_id)->not->toBe($firstRequestId)
        ->and($second->status)->toBe(ManagedTransitionStatus::Preparing)
        ->and($second->transition_id)->toBeNull();
});

it('transports only a structurally complete one-time mapping and rejects changed adoption roles', function (): void {
    $transition = p4bPrepared($fixture);
    $transition = app(ManagedTransitions::class)->fetchRoster($transition);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $mapping = [
        [
            'scalpels_id' => 'direct-member', 'local_kind' => null, 'local_id' => null,
            'role' => 'member', 'disposition' => 'create', 'final_email' => 'final@example.test',
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ];
    $proposed = app(ManagedTransitions::class)->propose($transition, $mapping);

    expect($proposed->status)->toBe(ManagedTransitionStatus::Proposed)
        ->and(DB::table('bfc_managed_transition_mappings')->count())->toBe(2);

    $mapping[0]['role'] = 'admin';
    expect(fn () => app(ManagedTransitions::class)->propose($proposed, $mapping))
        ->toThrow(ManagedAuthRefused::class, 'roster_changed')
        ->and(DB::table('bfc_managed_transition_mappings')->where('scalpels_id', 'direct-member')->value('role'))
        ->toBe('member');
});

it('refuses unsafe final mapping emails before staging data can be recorded', function (string $email): void {
    $transition = app(ManagedTransitions::class)->fetchRoster(p4bPrepared($fixture));
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $mapping = [
        [
            'scalpels_id' => 'direct-member', 'local_kind' => null, 'local_id' => null,
            'role' => 'member', 'disposition' => 'create', 'final_email' => $email,
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ];

    expect(fn () => app(ManagedTransitions::class)->propose($transition, $mapping))
        ->toThrow(ManagedAuthRefused::class)
        ->and(DB::table('bfc_managed_transition_mappings')->count())->toBe(0)
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Rostered);
})->with(["not\nan-address", str_repeat('a', 245).'@example.test']);

it('abandons a durably refused T3 and releases the installation for a replacement transition', function (): void {
    $transition = p4bProposed($fixture);
    $fixture->stageRosterChanged = true;

    expect(fn () => app(ManagedTransitions::class)->stage($transition))
        ->toThrow(ManagedAuthRefused::class, 'roster_changed')
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Staging)
        ->and($transition->fresh()->local_commit_receipt)->toBeNull()
        ->and(DB::table('users')->count())->toBe(1);

    $fixture->stageRosterChanged = false;
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $abandoned = app(ManagedTransitions::class)->abandon(p4bOwnerRequest($owner), $transition->fresh());
    $replacement = app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);

    expect($abandoned->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and($replacement->id)->not->toBe($abandoned->id)
        ->and($replacement->status)->toBe(ManagedTransitionStatus::Prepared);
});

it('converges a local staging attempt when T5 reports an authority-side abandon', function (): void {
    $transition = p4bProposed($fixture);
    $fixture->stageRosterChanged = true;
    expect(fn () => app(ManagedTransitions::class)->stage($transition))
        ->toThrow(ManagedAuthRefused::class, 'roster_changed');
    $transition = $transition->fresh();
    $key = str_repeat('a', 43);
    $body = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $key,
        'abandon_request_body' => $body,
        'abandon_body_digest' => hash('sha256', $body),
    ])->save();
    p4bClient($transition->fresh())->abandon();

    expect(app(ManagedTransitions::class)->recover($transition->fresh())->status)
        ->toBe(ManagedTransitionStatus::Abandoned);
});

it('rejects every transition leg when a frozen identity binding is crossed', function (string $leg, string $field): void {
    if ($leg === 'T1') {
        [$owner, $fixture] = p4bConfigure();
        $fixture->transform = static function (string $responseLeg, array $payload) use ($field): array {
            if ($responseLeg === 'T1') {
                $payload[$field] = match ($field) {
                    'authority_generation' => 8,
                    default => 'crossed-'.$field,
                };
            }

            return $payload;
        };
        expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
            ->toThrow(ManagedAuthRefused::class);

        return;
    }

    $transition = $leg === 'T3' ? p4bProposed($fixture) : p4bPrepared($fixture);
    $fixture->transform = static function (string $responseLeg, array $payload) use ($leg, $field): array {
        if ($responseLeg === $leg) {
            $payload[$field] = match ($field) {
                'authority_generation' => 8,
                default => 'crossed-'.$field,
            };
        }

        return $payload;
    };
    $before = p4bProtectedState();

    $operation = match ($leg) {
        'T2' => fn (): ManagedTransition => app(ManagedTransitions::class)->fetchRoster($transition),
        'T3' => fn (): ManagedTransition => app(ManagedTransitions::class)->stage($transition),
        'T5' => fn () => p4bClient($transition)->state(),
    };
    expect($operation)->toThrow(ManagedAuthRefused::class);

    if ($leg !== 'T3') {
        expect(p4bProtectedState())->toBe($before);
    } else {
        expect($transition->fresh()->status)->toBe(ManagedTransitionStatus::Staging)
            ->and($transition->fresh()->local_commit_receipt)->toBeNull();
    }
})->with([
    ['T1', 'issuer'],
    ['T1', 'connection_id'],
    ['T1', 'organization_id'],
    ['T1', 'installation_id'],
    ['T2', 'issuer'],
    ['T2', 'connection_id'],
    ['T2', 'organization_id'],
    ['T2', 'installation_id'],
    ['T3', 'issuer'],
    ['T3', 'connection_id'],
    ['T3', 'organization_id'],
    ['T3', 'installation_id'],
    ['T5', 'issuer'],
    ['T5', 'connection_id'],
    ['T5', 'organization_id'],
    ['T5', 'installation_id'],
]);

it('refuses impossible authority status generation receipt tuples without mutation', function (array $changes): void {
    $transition = p4bPrepared($fixture);
    $fixture->transform = static function (string $leg, array $payload) use ($changes): array {
        return $leg === 'T5' ? array_replace($payload, $changes) : $payload;
    };
    $before = p4bProtectedState();

    expect(fn () => p4bClient($transition)->state())
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4bProtectedState())->toBe($before);
})->with([
    'prepared at G+1' => [['authority_generation' => 8]],
    'prepared with receipt' => [['local_commit_receipt' => 'crossed-receipt']],
    'staged with receipt' => [['status' => 'staged', 'local_commit_receipt' => 'crossed-receipt']],
    'abandoned with receipt' => [['status' => 'abandoned', 'local_commit_receipt' => 'crossed-receipt']],
    'acknowledged at G' => [[
        'status' => 'acknowledged',
        'authority_generation' => 7,
        'local_commit_receipt' => 'crossed-receipt',
        'acknowledged_at' => '2026-09-11T12:05:00+00:00',
    ]],
    'acknowledged without timestamp' => [[
        'status' => 'acknowledged',
        'authority_generation' => 8,
        'local_commit_receipt' => 'crossed-receipt',
        'acknowledged_at' => null,
    ]],
    'acknowledged without package receipt' => [[
        'status' => 'acknowledged',
        'authority_generation' => 8,
        'local_commit_receipt' => null,
        'acknowledged_at' => '2026-09-11T12:05:00+00:00',
    ]],
]);

it('binds stage commit recovery and ack to the frozen direction and generation', function (string $point): void {
    $transition = p4bProposed($fixture);

    if ($point === 'stage') {
        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
        $before = $transition->fresh()->getAttributes();
        expect(fn () => app(ManagedTransitions::class)->stage($transition))
            ->toThrow(ManagedAuthRefused::class, 'transition_state_conflict')
            ->and($transition->fresh()->getAttributes())->toBe($before);

        return;
    }

    $transition = app(ManagedTransitions::class)->stage($transition);
    if ($point === 'commit') {
        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
        expect(fn () => app(ManagedTransitions::class)->commit($transition, static function (): void {}))
            ->toThrow(ManagedAuthRefused::class, 'transition_state_conflict')
            ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Staged);

        return;
    }

    $transition = app(ManagedTransitions::class)->commit($transition, static function (): void {
        if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed) === null) {
            throw new RuntimeException('Fixture failed to switch authority mode.');
        }
    });
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update(['generation' => 9]);

    expect(fn () => $point === 'ack'
        ? app(ManagedTransitions::class)->acknowledge($transition)
        : app(ManagedTransitions::class)->recover($transition))
        ->toThrow(ManagedAuthRefused::class, 'transition_state_conflict')
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Committed);
})->with(['stage', 'commit', 'recovery', 'ack']);

it('rolls local effects and authority mode back when commit cannot finish', function (string $failure): void {
    $transition = app(ManagedTransitions::class)->stage(p4bProposed($fixture));
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $before = p4bProtectedState();

    $commit = function () use ($transition, $owner, $failure): void {
        app(ManagedTransitions::class)->commit($transition, static function () use ($owner, $failure): void {
            $owner->forceFill(['name' => 'Must Roll Back'])->save();
            if ($failure === 'callback') {
                throw new RuntimeException('forced local effect failure');
            }
        });
    };

    expect($commit)->toThrow($failure === 'callback' ? RuntimeException::class : ManagedAuthRefused::class)
        ->and(p4bProtectedState())->toBe($before)
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Staged)
        ->and($transition->fresh()->local_commit_receipt)->toBeNull();
})->with(['callback', 'mode not switched']);

it('never rotates a recorded key after the authority reports idempotency conflict', function (): void {
    $transition = p4bPrepared($fixture);
    $key = str_repeat('k', 43);
    $body = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $key,
        'abandon_request_body' => $body,
        'abandon_body_digest' => hash('sha256', $body),
    ])->save();
    p4bClient($transition->refresh())->abandon();
    $changedBody = str_replace('transition-installation', 'other-installation', $body);
    $transition->forceFill([
        'abandon_request_body' => $changedBody,
        'abandon_body_digest' => hash('sha256', $changedBody),
    ])->save();

    expect(fn () => p4bClient($transition->refresh())->abandon())
        ->toThrow(ManagedAuthRefused::class, 'idempotency_conflict')
        ->and($transition->fresh()->abandon_idempotency_key)->toBe($key)
        ->and($fixture->executionCounts['T7'])->toBe(1);
});

it('refuses a T7 response whose roster version is not the frozen snapshot', function (): void {
    $transition = p4bPrepared($fixture);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $fixture->transform = static function (string $leg, array $payload): array {
        if ($leg === 'T7') {
            $payload['roster_version'] = 42;
        }

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->abandon(p4bOwnerRequest($owner), $transition))
        ->toThrow(ManagedAuthRefused::class)
        ->and($transition->fresh()->status)->toBe(ManagedTransitionStatus::Prepared)
        ->and($transition->fresh()->abandon_idempotency_key)->toBeString()
        ->and(ManagedTransition::query()->where('status', 'abandoned')->count())->toBe(0);
});

it('returns transition_in_progress before direction validation for a second prepare', function (ManagedTransitionDirection $second): void {
    [$owner, $fixture] = p4bConfigure();
    app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt);
    $beforeCalls = count($fixture->calls);

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, $second))
        ->toThrow(ManagedAuthRefused::class, 'transition_in_progress')
        ->and(ManagedTransition::query()->count())->toBe(1)
        ->and($fixture->calls)->toHaveCount($beforeCalls);
})->with([ManagedTransitionDirection::Adopt, ManagedTransitionDirection::Exit]);

it('rejects unsafe numeric and malformed transition envelopes before association', function (string $case): void {
    [$owner, $fixture] = p4bConfigure();
    $fixture->transform = static function (string $leg, array $payload) use ($case): array {
        if ($leg !== 'T1') {
            return $payload;
        }

        match ($case) {
            'roster total bound' => $payload['roster_total'] = 50_001,
            'safe integer bound' => $payload['roster_version'] = 9_007_199_254_740_992,
            'numeric string' => $payload['roster_total'] = '1',
            'null required' => $payload['roster_cutoff_at'] = null,
            'unknown status' => $payload['status'] = 'pending',
            default => null,
        };

        return $payload;
    };

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class)
        ->and(ManagedTransition::query()->sole()->status)->toBe(ManagedTransitionStatus::Preparing);
})->with(['roster total bound', 'safe integer bound', 'numeric string', 'null required', 'unknown status']);

it('binding-checks T4 T6 and T7 before terminal local mutation', function (string $leg, string $field, mixed $value): void {
    if ($leg === 'T6') {
        [$owner, $fixture] = p4bConfigure();
        $fixture->crashAfterExecution = 'T1';
        expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
            ->toThrow(ManagedAuthRefused::class);
        $transition = ManagedTransition::query()->sole();
    } elseif ($leg === 'T4') {
        $transition = p4bCommitted($fixture);
    } else {
        $transition = p4bPrepared($fixture);
    }

    $fixture->transform = static function (string $responseLeg, array $payload) use ($leg, $field, $value): array {
        if ($responseLeg === $leg) {
            $payload[$field] = $value;
        }

        return $payload;
    };

    $operation = match ($leg) {
        'T4' => fn (): ManagedTransition => app(ManagedTransitions::class)->acknowledge($transition),
        'T6' => fn (): ManagedTransition => app(ManagedTransitions::class)->recover($transition),
        'T7' => fn (): ManagedTransition => app(ManagedTransitions::class)->abandon(
            p4bOwnerRequest(User::query()->whereNotNull('owner_slot')->sole()),
            $transition,
        ),
    };
    expect($operation)->toThrow(ManagedAuthRefused::class)
        ->and(ManagedTransition::query()->whereIn('status', ['acknowledged', 'abandoned'])->count())->toBe(0);
})->with([
    'T4 issuer' => ['T4', 'issuer', 'crossed-issuer'],
    'T4 transition' => ['T4', 'transition_id', 'crossed-transition'],
    'T4 roster' => ['T4', 'roster_version', 42],
    'T4 generation' => ['T4', 'authority_generation', 7],
    'T4 receipt' => ['T4', 'local_commit_receipt', 'crossed-receipt'],
    'T6 issuer' => ['T6', 'issuer', 'crossed-issuer'],
    'T6 request' => ['T6', 'transition_request_id', 'crossed-request'],
    'T7 issuer' => ['T7', 'issuer', 'crossed-issuer'],
    'T7 transition' => ['T7', 'transition_id', 'crossed-transition'],
    'T7 roster' => ['T7', 'roster_version', 42],
]);

it('drives a valid exit through T1 T2 T3 local commit and exact T4 acknowledgement', function (): void {
    [$owner, $fixture] = p4bConfigure(ManagedTransitionDirection::Exit);
    $transition = app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Exit);
    $transition = app(ManagedTransitions::class)->fetchRoster($transition);
    $transition = app(ManagedTransitions::class)->propose($transition, [[
        'scalpels_id' => null,
        'local_kind' => 'user',
        'local_id' => (string) $owner->getKey(),
        'role' => 'owner',
        'disposition' => 'retain_local',
        'final_email' => 'standalone-owner@example.test',
    ]]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    $transition = app(ManagedTransitions::class)->commit($transition, static function (): void {
        if (InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Standalone) === null) {
            throw new RuntimeException('Fixture failed to exit managed mode.');
        }
    });
    $transition = app(ManagedTransitions::class)->acknowledge($transition);
    $ackBody = json_decode(collect($fixture->calls)->firstWhere('leg', 'T4')['body'], true, flags: JSON_THROW_ON_ERROR);

    expect($transition->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($ackBody['mode_after'])->toBe('standalone')
        ->and($ackBody['generation_after'])->toBe(8);
});

it('rejects encoded T2 bodies instead of decompressing beyond the byte bound', function (): void {
    $transition = p4bPrepared();
    $http = new Factory;
    $http->fake(['*' => $http->response('compressed bytes', 200, [
        'Content-Type' => 'application/json',
        'Content-Encoding' => 'gzip',
    ])]);

    expect(fn () => p4bClient($transition, $http)->roster(null))
        ->toThrow(ManagedAuthRefused::class)
        ->and(DB::table('bfc_managed_transition_roster_members')->count())->toBe(0);
});

it('refuses missing null and mistyped required response fields on every transition leg', function (string $leg): void {
    $transition = match ($leg) {
        'T1', 'T2', 'T5', 'T6', 'T7' => p4bPrepared($fixture),
        'T3' => p4bProposed($fixture),
        'T4' => p4bCommitted($fixture),
    };
    if (in_array($leg, ['T1', 'T6'], true)) {
        $transition->forceFill(['status' => ManagedTransitionStatus::Preparing])->save();
        $transition = $transition->refresh();
    }

    $common = [
        'contract_version' => [],
        'issuer' => [],
        'connection_id' => [],
        'organization_id' => [],
        'installation_id' => [],
        'authority_generation' => '7',
        'roster_version' => '41',
        'response_sequence' => '73',
        'responded_at' => [],
    ];
    $fields = [
        'T1' => [
            ...$common,
            'transition_request_id' => [],
            'transition_id' => [],
            'direction' => [],
            'status' => [],
            'roster_cutoff_at' => [],
            'roster_total' => '1',
        ],
        'T2' => [
            ...$common,
            'transition_id' => [],
            'roster_cutoff_at' => [],
            'members' => 'not-an-array',
            'next_cursor' => 42,
            'page_total' => '1',
            'members.0.scalpels_id' => [],
            'members.0.membership_status' => [],
            'members.0.role' => [],
            'members.0.display_name' => [],
            'members.0.contact_email' => [],
            'members.0.contact_email_verified' => 'true',
        ],
        'T3' => [
            ...$common,
            'transition_id' => [],
            'status' => [],
            'roster_cutoff_at' => [],
        ],
        'T4' => [
            ...$common,
            'transition_id' => [],
            'status' => [],
            'generation_after' => '8',
            'local_commit_receipt' => [],
            'acknowledged_at' => [],
        ],
        'T5' => [
            ...$common,
            'transition_id' => [],
            'direction' => [],
            'status' => [],
            'roster_cutoff_at' => [],
            'local_commit_receipt' => [],
            'acknowledged_at' => [],
        ],
        'T6' => [
            ...$common,
            'transition_request_id' => [],
            'transition_id' => [],
            'status' => [],
        ],
        'T7' => [
            ...$common,
            'transition_id' => [],
            'status' => [],
        ],
    ][$leg];
    $nullable = match ($leg) {
        'T2' => ['next_cursor'],
        'T5' => ['local_commit_receipt', 'acknowledged_at'],
        default => [],
    };
    $counter = 0;

    foreach ($fields as $field => $mistyped) {
        foreach (['missing', 'null', 'mistyped'] as $shape) {
            if ($shape === 'null' && in_array($field, $nullable, true)) {
                continue;
            }

            $counter++;
            if ($leg === 'T1') {
                $fixture = new ManagedTransitionAuthorityFixture;
            }
            $fixture->transform = static function (string $responseLeg, array $payload) use (
                $leg,
                $field,
                $shape,
                $mistyped,
            ): array {
                if ($responseLeg !== $leg) {
                    return $payload;
                }

                $segments = explode('.', $field);
                $target = &$payload;
                foreach (array_slice($segments, 0, -1) as $segment) {
                    $target = &$target[ctype_digit($segment) ? (int) $segment : $segment];
                }
                $last = end($segments);
                $key = ctype_digit($last) ? (int) $last : $last;
                if ($shape === 'missing') {
                    unset($target[$key]);
                } else {
                    $target[$key] = $shape === 'null' ? null : $mistyped;
                }

                return $payload;
            };

            $key = rtrim(strtr(base64_encode(hash('sha256', $leg.$field.$shape.$counter, true)), '+/', '-_'), '=');
            $http = new Factory;
            $http->fake(fn (ClientRequest $request): mixed => $fixture->respond($request));
            $operation = match ($leg) {
                'T1' => fn () => p4bClient($transition, $http)->prepare(),
                'T2' => fn () => p4bClient($transition, $http)->roster(null),
                'T3' => function () use ($transition, $key, $http): mixed {
                    $mapping = DB::table('bfc_managed_transition_mappings')
                        ->where('managed_transition_id', $transition->id)
                        ->orderBy('ordinal')
                        ->get(['scalpels_id', 'local_kind', 'local_id', 'role', 'disposition', 'final_email'])
                        ->map(static fn (object $row): array => (array) $row)
                        ->all();
                    $body = json_encode([
                        'connection_id' => $transition->connection_id,
                        'installation_id' => $transition->installation_id,
                        'idempotency_key' => $key,
                        'roster_version' => $transition->roster_version,
                        'roster_cutoff_at' => $transition->roster_cutoff_at,
                        'mapping' => $mapping,
                    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                    $transition->forceFill([
                        'status' => ManagedTransitionStatus::Staging,
                        'stage_idempotency_key' => $key,
                        'stage_request_body' => $body,
                        'stage_body_digest' => hash('sha256', $body),
                    ])->save();

                    return p4bClient($transition->refresh(), $http)->stage();
                },
                'T4' => function () use ($transition, $key, $http): mixed {
                    $body = json_encode([
                        'connection_id' => $transition->connection_id,
                        'installation_id' => $transition->installation_id,
                        'idempotency_key' => $key,
                        'local_commit_receipt' => $transition->local_commit_receipt,
                        'mode_after' => $transition->mode_after,
                        'generation_after' => $transition->generation_after,
                    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                    $transition->forceFill([
                        'status' => ManagedTransitionStatus::Acknowledging,
                        'ack_idempotency_key' => $key,
                        'ack_request_body' => $body,
                        'ack_body_digest' => hash('sha256', $body),
                    ])->save();

                    return p4bClient($transition->refresh(), $http)->acknowledge();
                },
                'T5' => fn () => p4bClient($transition, $http)->state(),
                'T6' => fn () => p4bClient($transition, $http)->recoverRequest(),
                'T7' => function () use ($transition, $key, $http): mixed {
                    $body = json_encode([
                        'connection_id' => $transition->connection_id,
                        'installation_id' => $transition->installation_id,
                        'idempotency_key' => $key,
                    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                    $transition->forceFill([
                        'abandon_idempotency_key' => $key,
                        'abandon_request_body' => $body,
                        'abandon_body_digest' => hash('sha256', $body),
                    ])->save();

                    return p4bClient($transition->refresh(), $http)->abandon();
                },
            };

            try {
                $operation();
                throw new RuntimeException($leg.' accepted '.$shape.' '.$field.'.');
            } catch (ManagedAuthRefused) {
                // Expected uniform boundary refusal.
            }
        }
    }

    expect($counter)->toBeGreaterThan(0);
})->with(['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7']);

it('refuses unknown enums on every leg that carries one', function (string $leg, string $field): void {
    $transition = match ($leg) {
        'T1', 'T2', 'T5', 'T6', 'T7' => p4bPrepared($fixture),
        'T3' => p4bProposed($fixture),
        'T4' => p4bCommitted($fixture),
    };
    if (in_array($leg, ['T1', 'T6'], true)) {
        $transition->forceFill(['status' => ManagedTransitionStatus::Preparing])->save();
        $transition = $transition->refresh();
    }
    if ($leg === 'T1') {
        $fixture = new ManagedTransitionAuthorityFixture;
    }
    $fixture->transform = static function (string $responseLeg, array $payload) use ($leg, $field): array {
        if ($responseLeg !== $leg) {
            return $payload;
        }

        if (str_starts_with($field, 'members.')) {
            $payload['members'][0][substr($field, strlen('members.'))] = 'unknown';
        } else {
            $payload[$field] = 'unknown';
        }

        return $payload;
    };

    $http = new Factory;
    $http->fake(fn (ClientRequest $request): mixed => $fixture->respond($request));
    $operation = match ($leg) {
        'T1' => fn () => p4bClient($transition, $http)->prepare(),
        'T2' => fn () => p4bClient($transition, $http)->roster(null),
        'T3' => fn () => (new ManagedTransitions($http))->stage($transition),
        'T4' => fn () => (new ManagedTransitions($http))->acknowledge($transition),
        'T5' => fn () => p4bClient($transition, $http)->state(),
        'T6' => fn () => p4bClient($transition, $http)->recoverRequest(),
        'T7' => function () use ($transition, $http): mixed {
            $key = str_repeat('u', 43);
            $body = json_encode([
                'connection_id' => $transition->connection_id,
                'installation_id' => $transition->installation_id,
                'idempotency_key' => $key,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $transition->forceFill([
                'abandon_idempotency_key' => $key,
                'abandon_request_body' => $body,
                'abandon_body_digest' => hash('sha256', $body),
            ])->save();

            return p4bClient($transition->refresh(), $http)->abandon();
        },
    };

    expect($operation)->toThrow(ManagedAuthRefused::class);
})->with([
    ['T1', 'direction'],
    ['T1', 'status'],
    ['T2', 'members.membership_status'],
    ['T2', 'members.role'],
    ['T3', 'status'],
    ['T4', 'status'],
    ['T5', 'direction'],
    ['T5', 'status'],
    ['T6', 'status'],
    ['T7', 'status'],
]);

it('refuses malformed and unlisted failure envelopes uniformly', function (array|string $body, int $status): void {
    $transition = p4bPrepared();
    $transition->forceFill(['status' => ManagedTransitionStatus::Preparing])->save();
    $http = new Factory;
    $http->fake(['*' => $http->response($body, $status)]);

    expect(fn () => p4bClient($transition->refresh(), $http)->prepare())
        ->toThrow(ManagedAuthRefused::class);
})->with([
    'failure without contract' => [['error' => 'server_error'], 500],
    'unlisted error' => [[
        'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
        'error' => 'invented_error',
    ], 418],
    'non-json body' => ['not json', 500],
]);

it('allows only a current seated Owner session to send T7', function (string $caller): void {
    $transition = p4bPrepared($fixture);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $request = match ($caller) {
        'unauthenticated' => Request::create('/abandon', 'POST'),
        'stale session' => p4bOwnerRequest($owner, $owner->auth_session_version + 1),
        'admin' => (function () use ($owner): Request {
            $owner->forceFill(['role' => 'admin'])->save();

            return p4bOwnerRequest($owner->refresh());
        })(),
        'member' => (function () use ($owner): Request {
            $owner->forceFill(['role' => 'member'])->save();

            return p4bOwnerRequest($owner->refresh());
        })(),
        'inactive owner' => (function () use ($owner): Request {
            $owner->forceFill(['status' => 'disabled'])->save();

            return p4bOwnerRequest($owner->refresh());
        })(),
    };
    $before = p4bProtectedState();

    expect(fn () => app(ManagedTransitions::class)->abandon($request, $transition))
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4bProtectedState())->toBe($before)
        ->and(collect($fixture->calls)->where('leg', 'T7'))->toHaveCount(0);
})->with(['unauthenticated', 'stale session', 'admin', 'member', 'inactive owner']);

it('abandons from each legal state without protected effects and releases the active slot', function (string $state): void {
    $transition = $state === 'staged' ? p4bProposed($fixture) : p4bPrepared($fixture);
    if ($state === 'rostered' || $state === 'proposed') {
        $transition = app(ManagedTransitions::class)->fetchRoster($transition);
    }
    if ($state === 'proposed') {
        $owner = User::query()->whereNotNull('owner_slot')->sole();
        $transition = app(ManagedTransitions::class)->propose($transition, [
            ['scalpels_id' => 'direct-member', 'local_kind' => null, 'local_id' => null, 'role' => 'member', 'disposition' => 'create', 'final_email' => 'direct-final@example.test'],
            ['scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(), 'role' => null, 'disposition' => 'exclude', 'final_email' => null],
        ]);
    }
    if ($state === 'staged') {
        $transition = app(ManagedTransitions::class)->stage($transition);
    }
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $beforeUser = $owner->getAttributes();
    $beforeAuthority = (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();

    $abandoned = app(ManagedTransitions::class)->abandon(p4bOwnerRequest($owner), $transition);
    $again = app(ManagedTransitions::class)->recover($abandoned);

    expect($abandoned->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and($again->status)->toBe(ManagedTransitionStatus::Abandoned)
        ->and($fixture->executionCounts['T7'])->toBe(1)
        ->and($owner->fresh()->getAttributes())->toBe($beforeUser)
        ->and((array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first())->toBe($beforeAuthority);

    $replacement = app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);
    expect($replacement->id)->not->toBe($abandoned->id);
})->with(['prepared', 'rostered', 'proposed', 'staged']);

it('replays response-lost T7 with the exact persisted octets and one authority execution', function (): void {
    $transition = p4bPrepared($fixture);
    $key = str_repeat('z', 43);
    $body = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $key,
        'abandon_request_body' => $body,
        'abandon_body_digest' => hash('sha256', $body),
    ])->save();
    $fixture->crashAfterExecution = 'T7';

    expect(fn () => p4bClient($transition->fresh())->abandon())
        ->toThrow(ManagedAuthRefused::class);
    $response = p4bClient($transition->fresh())->abandon();
    $calls = collect($fixture->calls)->where('leg', 'T7');

    expect($transition->fresh()->status)->toBe(ManagedTransitionStatus::Prepared)
        ->and($response->status)->toBe('abandoned')
        ->and($calls->pluck('body')->all())->toBe([$body, $body])
        ->and($calls->pluck('digest')->all())->toBe([hash('sha256', $body), hash('sha256', $body)])
        ->and($fixture->executionCounts['T7'])->toBe(1)
        ->and($transition->fresh()->abandon_idempotency_key)->toBe($key);
});

it('resolves an authority-side abandoned transition through both T5 and T6', function (): void {
    $transition = p4bPrepared($fixture);
    $key = str_repeat('v', 43);
    $body = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $key,
        'abandon_request_body' => $body,
        'abandon_body_digest' => hash('sha256', $body),
    ])->save();
    p4bClient($transition->fresh())->abandon();

    expect(p4bClient($transition->fresh())->state()->status)->toBe('abandoned');
    $transition->forceFill(['status' => ManagedTransitionStatus::Preparing])->save();
    $recovered = p4bClient($transition->fresh())->recoverRequest();

    expect($recovered->status)->toBe('abandoned')
        ->and($recovered->transitionId)->toBe($transition->transition_id)
        ->and(collect($fixture->calls)->pluck('leg')->all())->toBe(['T1', 'T7', 'T5', 'T6']);
});

it('parses invalid_transition for mutating legs against an abandoned authority transition', function (string $leg): void {
    $transition = p4bPrepared($fixture);
    $abandonKey = str_repeat('w', 43);
    $abandonBody = json_encode([
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $abandonKey,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'abandon_idempotency_key' => $abandonKey,
        'abandon_request_body' => $abandonBody,
        'abandon_body_digest' => hash('sha256', $abandonBody),
    ])->save();
    p4bClient($transition->fresh())->abandon();
    $key = str_repeat($leg === 'T3' ? '3' : '4', 43);
    $receipt = str_repeat('r', 43);
    $payload = $leg === 'T3' ? [
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
        'roster_version' => $transition->roster_version,
        'roster_cutoff_at' => $transition->roster_cutoff_at,
        'mapping' => [],
    ] : [
        'connection_id' => $transition->connection_id,
        'installation_id' => $transition->installation_id,
        'idempotency_key' => $key,
        'local_commit_receipt' => $receipt,
        'mode_after' => 'managed',
        'generation_after' => 8,
    ];
    $requestBody = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill($leg === 'T3' ? [
        'status' => ManagedTransitionStatus::Staging,
        'stage_idempotency_key' => $key,
        'stage_request_body' => $requestBody,
        'stage_body_digest' => hash('sha256', $requestBody),
    ] : [
        'status' => ManagedTransitionStatus::Acknowledging,
        'local_commit_receipt' => $receipt,
        'ack_idempotency_key' => $key,
        'ack_request_body' => $requestBody,
        'ack_body_digest' => hash('sha256', $requestBody),
    ])->save();
    $before = p4bProtectedState();
    $operation = $leg === 'T3'
        ? fn () => p4bClient($transition->fresh())->stage()
        : fn () => p4bClient($transition->fresh())->acknowledge();

    expect($operation)
        ->toThrow(ManagedAuthRefused::class, 'invalid_transition')
        ->and(p4bProtectedState())->toBe($before)
        ->and($fixture->executionCounts[$leg] ?? 0)->toBe(0);
})->with(['T3', 'T4']);

it('uses the database active slot for same and opposite direction attempts per installation', function (): void {
    [$owner] = p4bConfigure();
    $first = app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt);

    expect(fn () => ManagedTransition::query()->create([
        ...$first->getAttributes(),
        'id' => (string) Str::uuid(),
        'transition_request_id' => str_repeat('x', 43),
        'direction' => ManagedTransitionDirection::Exit,
    ]))->toThrow(QueryException::class)
        ->and(ManagedTransition::query()->count())->toBe(1);
});

it('refuses copied stale terminal and foreign transition capabilities before HTTP', function (string $case): void {
    $transition = p4bPrepared($fixture);
    $subject = match ($case) {
        'copy' => $transition->replicate()->forceFill(['id' => (string) Str::uuid()]),
        'stale' => (function () use ($transition): ManagedTransition {
            $stale = clone $transition;
            $transition->forceFill(['status' => ManagedTransitionStatus::Rostered])->save();

            return $stale;
        })(),
        'terminal' => (function () use ($transition): ManagedTransition {
            $transition->forceFill(['status' => ManagedTransitionStatus::Acknowledged])->save();

            return $transition->refresh();
        })(),
        'abandoned' => (function () use ($transition): ManagedTransition {
            $transition->forceFill(['status' => ManagedTransitionStatus::Abandoned])->save();

            return $transition->refresh();
        })(),
        'foreign' => (clone $transition)->forceFill(['installation_id' => 'foreign-installation']),
    };
    $beforeCalls = count($fixture->calls);

    expect(fn () => p4bClient($subject)->roster(null))
        ->toThrow(ManagedAuthRefused::class)
        ->and($fixture->calls)->toHaveCount($beforeCalls);
})->with(['copy', 'stale', 'terminal', 'abandoned', 'foreign']);

it('confines each client instance to its one persisted same-installation attempt', function (): void {
    $first = p4bPrepared($fixture);
    $owner = User::query()->whereNotNull('owner_slot')->sole();
    $first = app(ManagedTransitions::class)->abandon(p4bOwnerRequest($owner), $first);
    $second = app(ManagedTransitions::class)->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);
    $secondClient = p4bClient($second);
    $beforeCalls = count($fixture->calls);

    expect(fn () => p4bClient($first)->roster(null))
        ->toThrow(ManagedAuthRefused::class)
        ->and($fixture->calls)->toHaveCount($beforeCalls)
        ->and($secondClient->roster(null)->members[0]->scalpelsId)->toBe('direct-member')
        ->and(collect($fixture->calls)->last()['path'])->toContain(rawurlencode((string) $second->transition_id))
        ->and(collect($fixture->calls)->last()['path'])->not->toContain(rawurlencode((string) $first->transition_id));
});

it('binds direction to the required starting mode before T1 with zero transition writes', function (ManagedTransitionDirection $direction): void {
    [$owner] = p4bConfigure($direction === ManagedTransitionDirection::Adopt
        ? ManagedTransitionDirection::Exit
        : ManagedTransitionDirection::Adopt);

    expect(fn () => app(ManagedTransitions::class)->prepare($owner, $direction))
        ->toThrow(ManagedAuthRefused::class)
        ->and(ManagedTransition::query()->count())->toBe(0);
})->with([ManagedTransitionDirection::Adopt, ManagedTransitionDirection::Exit]);
