<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/** @return array{0: User, 1: ManagedTransitionAuthorityFixture} */
function p4cConfigure(ManagedTransitionDirection $direction = ManagedTransitionDirection::Adopt): array
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => $direction->modeBefore()->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_base_url' => 'https://transition-authority.example.test',
        'managed_connection_status' => 'active',
    ]);
    config([
        'built-for-cloud.managed.client_secret' => 'transition-secret',
        'built-for-cloud.managed.ca_bundle' => null,
        'built-for-cloud.ui.managed_transitions' => true,
    ]);
    $owner = User::query()->create([
        'name' => 'Surface Owner',
        'email' => 'surface-owner@example.test',
    ]);
    $owner->forceFill([
        'role' => UserRole::Owner->value,
        'status' => 'active',
        'membership_confirmed_at' => now(),
        ...($direction === ManagedTransitionDirection::Exit ? [
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'transition-connection',
            'scalpels_id' => 'direct-member',
            'managed_membership_status' => 'active',
            'managed_membership_role' => 'owner',
        ] : []),
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture;
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    return [$owner->refresh(), $fixture];
}

function p4cInvitation(string $email = 'pending-surface@example.test'): Invitation
{
    return Invitation::factory()->create([
        'email' => $email,
        'role' => UserRole::Admin->value,
        'expires_at' => now()->addHour(),
    ]);
}

function p4cBegin(TestCase $test, User $owner, ManagedTransitionDirection $direction): ManagedTransition
{
    $test->actingAsVersioned($owner)
        ->post(route('bfc.transitions.store', $direction->value, false))
        ->assertRedirect();

    return ManagedTransition::query()->sole();
}

it('mounts the Owner proposal routes behind the package human gate', function (): void {
    foreach (['bfc.transitions.index', 'bfc.transitions.store', 'bfc.transitions.edit', 'bfc.transitions.update'] as $name) {
        $route = Route::getRoutes()->getByName($name);

        expect($route, $name)->not->toBeNull();
        expect($this->app['router']->gatherRouteMiddleware($route), $name)
            ->toContain(EnsureUserIsAuthenticated::class);
    }
});

it('shows a never-visited roster subject and every tagged local identity without an adoption role control', function (): void {
    [$owner] = p4cConfigure();
    $lookalike = User::query()->create([
        'name' => 'Direct Member Lookalike',
        'email' => 'lookalike-local@example.test',
    ]);
    $lookalike->forceFill([
        'role' => 'member',
        'original_contact_email' => 'lookalike-contact@example.test',
        'email_is_generated' => true,
    ])->save();
    $invitation = p4cInvitation();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-roster"')
        ->assertSee('direct-member')
        ->assertSee('Direct Member')
        ->assertSeeHtml('data-testid="transition-locals"')
        ->assertSee('local_kind: user / local_id: '.$lookalike->getKey())
        ->assertSee('local_kind: invitation / local_id: '.$invitation->getKey())
        ->assertSee('generated local address')
        ->assertSee('lookalike-contact@example.test')
        ->assertDontSeeHtml('data-testid="transition-disposition-control"')
        ->assertDontSeeHtml('data-testid="transition-role-control"');

    expect(DB::table('bfc_managed_transition_mappings')->count())->toBe(4)
        ->and(DB::table('bfc_managed_transition_mappings')->where('scalpels_id', 'direct-member')->value('role'))->toBe('member');
});

it('persists corrected matches and final email across reload and sends that stored mapping to T3', function (): void {
    [$owner, $fixture] = p4cConfigure();
    $invitation = p4cInvitation();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);

    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'link:invitation:'.$invitation->getKey(),
            'final_email' => 'corrected-stage@example.test',
        ]],
        'locals' => [
            ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
            ['local_kind' => 'invitation', 'local_id' => (string) $invitation->getKey()],
        ],
    ])->assertRedirect(route('bfc.transitions.edit', $transition));

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSee('corrected-stage@example.test')
        ->assertSeeHtml('data-testid="transition-email-provenance-owner-corrected"')
        ->assertSee('keeps invitation '.$invitation->getKey().' and its attribution');

    app(ManagedTransitions::class)->stage($transition->fresh());
    $stage = collect($fixture->calls)->sole('leg', 'T3');
    $sent = json_decode($stage['body'], true, flags: JSON_THROW_ON_ERROR)['mapping'];

    expect(collect($sent)->firstWhere('scalpels_id', 'direct-member'))->toMatchArray([
        'local_kind' => 'invitation',
        'local_id' => (string) $invitation->getKey(),
        'role' => 'member',
        'disposition' => 'link',
        'final_email' => 'corrected-stage@example.test',
    ]);
});

it('displays and clears the renewed email conflict source from test-created identity data', function (): void {
    [$owner] = p4cConfigure();
    $owner->forceFill([
        'email_conflict_at' => now(),
        'email_conflict_source' => 'renewed-authority-contact@example.test',
    ])->save();
    $transition = p4cBegin($this, $owner->refresh(), ManagedTransitionDirection::Adopt);

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-email-conflict"')
        ->assertSee('renewed-authority-contact@example.test');

    $owner->forceFill(['email_conflict_at' => null])->save();
    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertDontSeeHtml('data-testid="transition-email-conflict"')
        ->assertDontSee('renewed-authority-contact@example.test');
});

it('offers exit role corrections while keeping retained invitation fields and roster-only subjects immutable', function (): void {
    [$owner, $fixture] = p4cConfigure(ManagedTransitionDirection::Exit);
    $fixture->rosterPages['NULL'][] = [
        'scalpels_id' => 'never-visited-on-exit',
        'membership_status' => 'active',
        'role' => 'admin',
        'display_name' => 'Exit Roster Only',
        'contact_email' => 'exit-roster-only@example.test',
        'contact_email_verified' => true,
    ];
    $local = User::query()->create(['name' => 'Exit Local', 'email' => 'exit-local@example.test']);
    $local->forceFill(['role' => 'member'])->save();
    $invitation = p4cInvitation('exit-invitation@example.test');
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Exit);

    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'locals' => [
            [
                'local_kind' => 'user',
                'local_id' => (string) $owner->getKey(),
                'choice' => 'link:direct-member',
                'role' => 'owner',
                'final_email' => $owner->email,
            ],
            [
                'local_kind' => 'user',
                'local_id' => (string) $local->getKey(),
                'choice' => 'retain_local',
                'role' => 'admin',
                'final_email' => 'exit-corrected@example.test',
            ],
            [
                'local_kind' => 'invitation',
                'local_id' => (string) $invitation->getKey(),
                'choice' => 'retain_local',
            ],
        ],
    ])->assertRedirect();

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-role-control"')
        ->assertSeeHtml('data-testid="transition-invitation-fixed"')
        ->assertSee('exit-invitation@example.test')
        ->assertSee('never-visited-on-exit')
        ->assertSeeHtml('data-testid="transition-roster-informational"')
        ->assertSee('exit-corrected@example.test')
        ->assertSeeHtml('data-testid="transition-email-provenance-owner-corrected"')
        ->assertSee('local_kind: user / local_id: '.$local->getKey())
        ->assertSee('local_kind: invitation / local_id: '.$invitation->getKey());

    app(ManagedTransitions::class)->stage($transition->fresh());
    $stage = collect($fixture->calls)->sole('leg', 'T3');
    $sent = collect(json_decode($stage['body'], true, flags: JSON_THROW_ON_ERROR)['mapping']);
    expect($sent->pluck('scalpels_id')->filter()->all())->toBe(['direct-member'])
        ->and($sent->contains('scalpels_id', 'never-visited-on-exit'))->toBeFalse()
        ->and($sent->firstWhere('local_id', (string) $local->getKey()))->toMatchArray([
            'role' => 'admin',
            'final_email' => 'exit-corrected@example.test',
        ]);
});

it('keeps Owner, completeness, and unique-email enforcement active with every UI affordance off', function (): void {
    [$owner, $fixture] = p4cConfigure();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);
    config(['built-for-cloud.ui' => ['managed_transitions' => false]]);
    $admin = User::query()->create(['name' => 'Surface Admin', 'email' => 'surface-admin@example.test']);
    $admin->forceFill(['role' => 'admin'])->save();
    $member = User::query()->create(['name' => 'Surface Member', 'email' => 'surface-member@example.test']);
    $member->forceFill(['role' => 'member'])->save();

    $this->actingAsVersioned($admin)->get(route('bfc.transitions.edit', $transition, false))->assertForbidden();
    $this->actingAsVersioned($member)->get(route('bfc.transitions.edit', $transition, false))->assertForbidden();
    $this->actingAsVersioned($admin)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [],
        'locals' => [],
    ])->assertForbidden();
    auth()->logout();
    $this->get(route('bfc.transitions.edit', $transition, false))->assertRedirect(route('bfc.login'));

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('<fieldset disabled')
        ->assertDontSeeHtml('data-testid="transition-save-control"');

    $before = DB::table('bfc_managed_transition_mappings')->orderBy('ordinal')->get()->map(fn (object $row): array => (array) $row)->all();
    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'create',
            'final_email' => 'complete-check@example.test',
        ]],
        'locals' => [],
    ])->assertSessionHasErrors('mapping');

    $locals = [
        ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
        ['local_kind' => 'user', 'local_id' => (string) $admin->getKey()],
        ['local_kind' => 'user', 'local_id' => (string) $member->getKey()],
    ];
    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'create',
            'final_email' => $owner->email,
        ]],
        'locals' => $locals,
    ])->assertSessionHasErrors('mapping');

    expect(DB::table('bfc_managed_transition_mappings')->orderBy('ordinal')->get()->map(fn (object $row): array => (array) $row)->all())->toBe($before)
        ->and(collect($fixture->calls)->where('leg', 'T3'))->toHaveCount(0);
});

it('revalidates complete local identity coverage immediately before T3', function (): void {
    [$owner, $fixture] = p4cConfigure();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);
    $late = User::query()->create(['name' => 'Late Local Identity', 'email' => 'late-local@example.test']);
    $late->forceFill(['role' => 'member'])->save();

    expect(fn () => app(ManagedTransitions::class)->stage($transition->fresh()))
        ->toThrow(ManagedAuthRefused::class)
        ->and($transition->fresh()->status->value)->toBe('proposed')
        ->and(collect($fixture->calls)->where('leg', 'T3'))->toHaveCount(0);
});

it('persists the managed JIT timing disposition without claiming admission control', function (): void {
    [$owner, $fixture] = p4cConfigure();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);

    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'defer_to_managed_jit',
            'final_email' => 'ignored-for-deferred@example.test',
        ]],
        'locals' => [
            ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
        ],
    ])->assertRedirect();

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSee('direct-member')
        ->assertSeeHtml('<option value="defer_to_managed_jit" selected>');

    app(ManagedTransitions::class)->stage($transition->fresh());
    $stage = collect($fixture->calls)->sole('leg', 'T3');
    $subject = collect(json_decode($stage['body'], true, flags: JSON_THROW_ON_ERROR)['mapping'])
        ->firstWhere('scalpels_id', 'direct-member');

    expect($subject)->toMatchArray([
        'role' => null,
        'disposition' => 'defer_to_managed_jit',
        'final_email' => null,
    ]);
});

it('revalidates a persisted staging request before a T3 recovery retry', function (): void {
    [$owner, $fixture] = p4cConfigure();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);
    $fixture->crashBeforeExecution = 'T3';

    expect(fn () => app(ManagedTransitions::class)->stage($transition->fresh()))
        ->toThrow(ManagedAuthRefused::class);
    $late = User::query()->create(['name' => 'Late Recovery Identity', 'email' => 'late-recovery@example.test']);
    $late->forceFill(['role' => 'member'])->save();

    expect(fn () => app(ManagedTransitions::class)->recover($transition->fresh()))
        ->toThrow(ManagedAuthRefused::class)
        ->and($transition->fresh()->status->value)->toBe('staging')
        ->and(collect($fixture->calls)->where('leg', 'T3'))->toHaveCount(1)
        ->and($fixture->executionCounts['T3'] ?? 0)->toBe(0);
});
