<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ClaimError;
use ArtisanBuild\BuiltForCloud\Contracts\ComposesInvitedUserAttributes;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

// PR8 locked AC 1 (model path): the ttl is REQUIRED and bounded — the old
// 7-day default is deleted, and the signature makes its absence a type
// error, so no hidden default can exist on this path.

it('refuses invitation ttls outside the claim-code bounds on the model path', function (): void {
    expect(fn (): Invitation => Invitation::invite('bounds@user.test', 59))
        ->toThrow(InvalidCredentialInput::class)
        ->and(fn (): Invitation => Invitation::invite('bounds@user.test', 604801))
        ->toThrow(InvalidCredentialInput::class)
        ->and(Invitation::query()->count())->toBe(0);
});

it('sets expiry to exactly issue time plus the chosen ttl — no hidden default', function (): void {
    $this->freezeTime();

    $invitation = Invitation::invite('exact@user.test', 3600);

    expect($invitation->expires_at?->timestamp)->toBe(now()->addSeconds(3600)->timestamp);

    $minimum = Invitation::invite('minimum@user.test', 60);
    $maximum = Invitation::invite('maximum@user.test', 604800);

    expect($minimum->expires_at?->timestamp)->toBe(now()->addSeconds(60)->timestamp)
        ->and($maximum->expires_at?->timestamp)->toBe(now()->addSeconds(604800)->timestamp);
});

// PR8 locked AC 2: the at_exchange burn — acceptance consumes under a
// conditional update gated on affected rows, and the accept path speaks
// the claim error enum.

it('refuses the second accept as code_already_claimed', function (): void {
    $invitation = Invitation::invite('once@user.test', 3600);
    $code = $invitation->token;

    Invitation::accept($code, ['name' => 'Once', 'password' => 'pw']);

    try {
        Invitation::accept($code, ['name' => 'Twice', 'password' => 'pw']);
        $this->fail('The second accept was not refused.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeAlreadyClaimed);
    }

    expect(User::query()->count())->toBe(1);
});

it('speaks the claim error enum for unknown and expired invitations, without echoing the code', function (): void {
    $unknownCode = 'unknown-'.Str::random(32);

    try {
        Invitation::accept($unknownCode, ['name' => 'Nobody', 'password' => 'pw']);
        $this->fail('An unknown invitation was accepted.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeNotFound);
        $this->assertExceptionCarriesNoSecret($refusal, $unknownCode);
    }

    $expiredCode = 'expired-'.Str::random(32);

    Invitation::factory()->create([
        'email' => 'expired@user.test',
        'token' => hash('sha256', $expiredCode),
        'expires_at' => now()->subMinute(),
    ]);

    try {
        Invitation::accept($expiredCode, ['name' => 'Late', 'password' => 'pw']);
        $this->fail('An expired invitation was accepted.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeExpired);
        $this->assertExceptionCarriesNoSecret($refusal, $expiredCode);
    }

    expect(User::query()->count())->toBe(0);
});

it('lets exactly one of two racing accepts win, decided at the affected-rows gate', function (): void {
    $invitation = Invitation::invite('race@user.test', 3600);
    $code = $invitation->token;
    $invitationId = $invitation->getKey();

    $competitorFired = false;

    DB::listen(function (QueryExecuted $query) use (&$competitorFired, $invitationId): void {
        // Between the loser's locked read and its conditional update, the
        // competing accept lands first — so the loser's update matches
        // zero rows and the gate must refuse it as already claimed.
        if (! $competitorFired
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'invitations')
            && str_contains($query->sql, 'token')) {
            $competitorFired = true;

            DB::table('invitations')
                ->where('id', $invitationId)
                ->whereNull('accepted_at')
                ->update(['accepted_at' => now()]);
        }
    });

    try {
        Invitation::accept($code, ['name' => 'Loser', 'password' => 'pw']);
        $this->fail('The losing accept was not refused.');
    } catch (InvalidInvitation $refusal) {
        expect($refusal->error)->toBe(ClaimError::CodeAlreadyClaimed);
    }

    // The pre-read saw accepted_at NULL (the competitor fired only after
    // that SELECT), so this refusal can ONLY have come from the
    // affected-rows gate — the loser never created a user. The competing
    // write itself shares this test's single connection, so the loser's
    // rollback takes it too; the row's final state here is not the
    // two-connection production outcome and is not asserted.
    expect($competitorFired)->toBeTrue()
        ->and(User::query()->count())->toBe(0)
        ->and(Invitation::query()->whereKey($invitationId)->exists())->toBeTrue();
});

// PR8 locked AC 3: the attribute-composition hook — an app that binds one
// composes the created user; an app that binds nothing sees today's
// behaviour exactly (AuthFoundationTest's accept expectations run
// unmodified beyond the documented ttl-argument break).

it('composes user attributes through the registered accept hook', function (): void {
    app()->bind(ComposesInvitedUserAttributes::class, static fn (): ComposesInvitedUserAttributes => new class implements ComposesInvitedUserAttributes
    {
        public function composeInvitedUserAttributes(Invitation $invitation, array $attributes): array
        {
            // The capstan shape: the stored role is projected onto the
            // user at creation (the fixture user has no org_role column,
            // so the projection lands on name).
            $attributes['name'] = 'role:'.($invitation->role ?? 'none');

            return $attributes;
        }
    });

    $invitation = Invitation::invite('composed@user.test', 3600, invitedBy: '42', role: 'editor');

    $user = Invitation::accept($invitation->token, ['name' => 'Ignored', 'password' => 'pw']);

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->refresh()->name)->toBe('role:editor')
        ->and(Invitation::query()->whereKey($invitation->getKey())->value('role'))->toBe('editor')
        ->and(Invitation::query()->whereKey($invitation->getKey())->value('invited_by'))->toBe('42');
});

it('strips admin escalation from the hook output and keeps the addressed email authoritative', function (): void {
    app()->bind(ComposesInvitedUserAttributes::class, static fn (): ComposesInvitedUserAttributes => new class implements ComposesInvitedUserAttributes
    {
        public function composeInvitedUserAttributes(Invitation $invitation, array $attributes): array
        {
            $attributes['is_admin'] = true;
            $attributes['email'] = 'hijacked@user.test';

            return $attributes;
        }
    });

    $invitation = Invitation::invite('victim@user.test', 3600);

    $user = Invitation::accept($invitation->token, ['name' => 'Composed', 'password' => 'pw']);

    expect($user->refresh()->email)->toBe('victim@user.test')
        ->and($user->is_admin)->toBeFalse();
});

// PR8 locked AC 4 (accept side): open invitations work end-to-end.

it('accepts an open invitation with the registrant-supplied email and stamps used_by', function (): void {
    $invitation = Invitation::invite(null, 3600);

    expect(Invitation::query()->whereKey($invitation->getKey())->value('email'))->toBeNull();

    $user = Invitation::accept($invitation->token, [
        'name' => 'Open Registrant',
        'email' => 'chosen@user.test',
        'password' => 'pw',
    ]);

    $invitation->refresh();

    expect($user->refresh()->email)->toBe('chosen@user.test')
        ->and($invitation->accepted_at)->not->toBeNull()
        ->and($invitation->used_by)->toBe((string) $user->getKey());
});

it('forces the addressed email over a registrant-supplied one', function (): void {
    $invitation = Invitation::invite('addressed@user.test', 3600);

    $user = Invitation::accept($invitation->token, [
        'name' => 'Addressed',
        'email' => 'other@user.test',
        'password' => 'pw',
    ]);

    expect($user->refresh()->email)->toBe('addressed@user.test');
});

// PR8 locked AC 5: the down() guards (FLT-F).

it('does not drop an app-owned invitations table on rollback when the package created nothing', function (): void {
    // The FLT-F scenario: the flag is off, the table exists because the
    // APP created it, and the package migration recorded as run having
    // created nothing. A rollback of that batch must not touch the table.
    config(['built-for-cloud.auth_foundation.invitations' => false]);

    Schema::dropIfExists('invitations');
    Schema::create('invitations', function (Blueprint $table): void {
        $table->id();
        $table->string('code')->unique();
    });

    $createMigration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $generalizeMigration = require __DIR__.'/../database/migrations/2026_08_28_600001_generalize_invitations_table.php';

    $generalizeMigration->down();
    $createMigration->down();

    expect(Schema::hasTable('invitations'))->toBeTrue()
        ->and(Schema::hasColumn('invitations', 'code'))->toBeTrue();
});

it('survives rollback when the invitations table is already gone', function (): void {
    Schema::dropIfExists('invitations');

    $createMigration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $createMigration->down();

    expect(Schema::hasTable('invitations'))->toBeFalse();
});

it('does not drop an app-owned invitations table on rollback even with the flag ON', function (): void {
    // The un-provable-ownership case (FLT-F): the flag is on, but up()
    // skipped because the APP's table pre-existed — flag-on +
    // table-present cannot prove whose table it is, so down() must not
    // drop it.
    Schema::dropIfExists('invitations');
    Schema::create('invitations', function (Blueprint $table): void {
        $table->id();
        $table->string('code')->unique();
    });

    $createMigration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $createMigration->up();
    $createMigration->down();

    expect(Schema::hasTable('invitations'))->toBeTrue()
        ->and(Schema::hasColumn('invitations', 'code'))->toBeTrue();
});

it('never drops even the table the package itself created — rollback is a documented no-op', function (): void {
    // The chosen Fix-4 semantics: because rollback cannot distinguish the
    // package's table from an app's, it drops NOTHING, ever; an operator
    // drops manually when they truly mean it (release note).
    expect(Schema::hasColumn('invitations', 'token'))->toBeTrue();

    $createMigration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $createMigration->down();

    expect(Schema::hasTable('invitations'))->toBeTrue()
        ->and(Schema::hasColumn('invitations', 'token'))->toBeTrue();
});

it('never generalizes an app-shaped invitations table', function (): void {
    // The additive migration is guarded on the PACKAGE's shape: an
    // invitations table without the hashed token column belongs to the
    // app and is not reshaped, even with the flag on.
    Schema::dropIfExists('invitations');
    Schema::create('invitations', function (Blueprint $table): void {
        $table->id();
        $table->string('code')->unique();
    });

    $generalizeMigration = require __DIR__.'/../database/migrations/2026_08_28_600001_generalize_invitations_table.php';
    $generalizeMigration->up();

    expect(Schema::hasColumn('invitations', 'used_by'))->toBeFalse()
        ->and(Schema::hasColumn('invitations', 'role'))->toBeFalse();
});

// PR8 locked AC 8 (accept side): the exchanged event rides the accept's
// own transaction with its outbox row.

it('records the exchanged audit event with its outbox row when an invitation is accepted', function (): void {
    $invitation = Invitation::invite('audited@user.test', 3600);

    Invitation::accept($invitation->token, ['name' => 'Audited', 'password' => 'pw']);

    $exchanged = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Exchanged->value)
        ->where('code_id', $invitation->getKey())
        ->sole();

    expect($exchanged->recipient)->toBe('audited@user.test')
        ->and($exchanged->actor_ref)->toBe($invitation->getKey())
        ->and(CredentialOutboxEntry::query()->where('audit_event_id', $exchanged->id)->exists())->toBeTrue();
});

// Judge fold (AC 8): the exchanged audit row, its outbox row, the burn
// and the created user are ONE transaction — a failure after the
// recorder call rolls everything back together (the PR4 sabotage
// pattern). A recorder call moved outside the transaction would leave
// the mutation standing while the audit write failed; this catches it.

it('rolls the user, burn, audit row and outbox row back together when the accept transaction dies late', function (): void {
    $invitation = Invitation::invite('doomed-accept@user.test', 3600);
    $code = $invitation->token;

    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed): void {
        if ($armed
            && preg_match('/^\s*insert\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credential_outbox')) {
            $armed = false;

            throw new RuntimeException('simulated process death after the outbox write');
        }
    });

    expect(fn (): mixed => Invitation::accept($code, ['name' => 'Doomed', 'password' => 'pw']))
        ->toThrow(RuntimeException::class);

    $invitation->refresh();

    // EVERYTHING rolled back: the burn, the user, the audit row and the
    // outbox row — and a retry then succeeds normally.
    expect($invitation->accepted_at)->toBeNull()
        ->and($invitation->used_by)->toBeNull()
        ->and(User::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0)
        ->and(CredentialOutboxEntry::query()->count())->toBe(0);

    $user = Invitation::accept($code, ['name' => 'Retry', 'password' => 'pw']);

    expect($user)->toBeInstanceOf(User::class)
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::Exchanged->value)->count())->toBe(1);
});

// PR8 locked AC 9 (model side): the code egresses only through the
// documented boundary; accept leaks nothing.

it('leaks nothing through the side channels when inviting and accepting', function (): void {
    /** @var Invitation $invitation */
    $invitation = $this->assertNoSecretLeakageOfMinted(
        fn (): Invitation => Invitation::invite('contained@user.test', 3600),
        fn (Invitation $invitation): string => $invitation->token,
    );

    $code = $invitation->token;

    $this->assertNoSecretLeakage($code, fn (): mixed => Invitation::accept($code, [
        'name' => 'Contained',
        'password' => 'pw',
    ]));

    expect(Invitation::query()->whereKey($invitation->getKey())->value('token'))->toBe(hash('sha256', $code));
});
