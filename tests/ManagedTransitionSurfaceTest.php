<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneMemberships;
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
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ViewErrorBag;

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
    [$owner, $fixture] = p4cConfigure();
    $fixture->rosterPages['NULL'][0]['display_name'] = 'Test-created roster subject';
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

    $response = $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-adopt-authority-fixed"')
        ->assertSee('Roles and membership come from the Team Account authority. You can correct local matches, commit timing, and final local emails; authority roles are not editable here.')
        ->assertSeeHtml('data-testid="transition-roster"')
        ->assertSee('direct-member')
        ->assertSeeHtml('<strong>Test-created roster subject</strong>')
        ->assertSeeHtml('Authority role: <strong>member</strong>')
        ->assertSeeHtml('data-testid="transition-match-control"')
        ->assertSeeHtml('data-testid="transition-email-provenance-authority-contact"')
        ->assertSee('Final email direct-member@example.test provenance: authority contact')
        ->assertSeeHtml('data-testid="transition-consequence-roster-create"')
        ->assertSee('subject direct-member creates a local user at commit with authority contact direct-member@example.test.')
        ->assertSeeHtml('data-testid="transition-locals"')
        ->assertSee('local_kind: user / local_id: '.$lookalike->getKey())
        ->assertSee('local_kind: invitation / local_id: '.$invitation->getKey())
        ->assertSee('generated local address')
        ->assertSee('lookalike-contact@example.test')
        ->assertSeeHtml('data-testid="transition-consequence-user-exclude"')
        ->assertSee('deactivates this user without deleting local ID '.$lookalike->getKey().' or its attribution.')
        ->assertSeeHtml('data-testid="transition-consequence-invitation-exclude"')
        ->assertSee('cancels invitation '.$invitation->getKey().' without creating or deleting a user row.');

    expect($response->getContent())->not->toMatch('/name="roster\[\d+\]\[role\]"/');

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
        ]],
        'locals' => [
            ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
            ['local_kind' => 'invitation', 'local_id' => (string) $invitation->getKey()],
        ],
    ])->assertRedirect(route('bfc.transitions.edit', $transition));

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-email-provenance-invitation-contact"')
        ->assertSee('Final email '.$invitation->email.' provenance: stored invitee contact')
        ->assertSeeHtml('data-testid="transition-consequence-roster-link"')
        ->assertSee('subject direct-member keeps invitation '.$invitation->getKey().' and its attribution.')
        ->assertSeeHtml('data-testid="transition-consequence-invitation-link"')
        ->assertSee('invitation '.$invitation->getKey().' creates a user for the matched subject and is consumed as accepted.');

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
        ->assertSee('Final email corrected-stage@example.test provenance: Owner-corrected local address');

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

it('re-matches a deferred roster subject using the selected local identity email', function (): void {
    [$owner] = p4cConfigure();
    $colliding = User::query()->create([
        'name' => 'Authority Contact Holder',
        'email' => 'direct-member@example.test',
    ]);
    $colliding->forceFill(['role' => 'member'])->save();
    $selected = User::query()->create([
        'name' => 'Selected Local Identity',
        'email' => 'selected-local@example.test',
    ]);
    $selected->forceFill(['role' => 'member'])->save();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);

    expect(DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'direct-member')
        ->value('disposition'))->toBe('defer_to_managed_jit');
    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertDontSeeHtml('name="roster[0][final_email]"');

    $locals = [
        ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
        ['local_kind' => 'user', 'local_id' => (string) $colliding->getKey()],
        ['local_kind' => 'user', 'local_id' => (string) $selected->getKey()],
    ];
    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'link:user:'.$selected->getKey(),
        ]],
        'locals' => $locals,
    ])->assertRedirect(route('bfc.transitions.edit', $transition));

    $stored = DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'direct-member')
        ->first();
    expect($stored)->not->toBeNull()
        ->and($stored->local_kind)->toBe('user')
        ->and($stored->local_id)->toBe((string) $selected->getKey())
        ->and($stored->final_email)->toBe($selected->email);

    $this->actingAsVersioned($owner)->put(route('bfc.transitions.update', $transition, false), [
        'roster' => [[
            'scalpels_id' => 'direct-member',
            'choice' => 'link:user:'.$selected->getKey(),
            'final_email' => $colliding->email,
        ]],
        'locals' => $locals,
    ])->assertSessionHasErrors('mapping');

    expect(DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'direct-member')
        ->value('final_email'))->toBe($selected->email);
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
    $generated = User::query()->create(['name' => 'Exit Generated', 'email' => 'exit-generated@example.test']);
    $generated->forceFill(['role' => 'member', 'email_is_generated' => true])->save();
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
            [
                'local_kind' => 'user',
                'local_id' => (string) $generated->getKey(),
                'choice' => 'retain_local',
                'role' => 'member',
                'final_email' => $generated->email,
            ],
        ],
    ])->assertRedirect();

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-role-control"')
        ->assertSeeHtml('data-testid="transition-invitation-fixed"')
        ->assertSee('Invitation '.$invitation->getKey().' remains pending with stored invitee email exit-invitation@example.test and invited role admin; neither field is editable.')
        ->assertSee('never-visited-on-exit')
        ->assertSeeHtml('data-testid="transition-roster-informational"')
        ->assertSee('Not carried into standalone.')
        ->assertSee('Roster subject never-visited-on-exit (exit-roster-only@example.test) has no local identity, so no mapping element is sent to stage.')
        ->assertSeeHtml('<p><strong>Proposed match:</strong> user '.$owner->getKey().'</p>')
        ->assertSee('exit-corrected@example.test')
        ->assertSeeHtml('data-testid="transition-email-provenance-owner-corrected"')
        ->assertSee('Final email exit-corrected@example.test provenance: Owner-corrected local address')
        ->assertSeeHtml('data-testid="transition-email-provenance-local-contact"')
        ->assertSee('Final email '.$owner->email.' provenance: current local contact')
        ->assertSeeHtml('data-testid="transition-email-provenance-generated"')
        ->assertSee('Final email exit-generated@example.test provenance: generated local address')
        ->assertSeeHtml('data-testid="transition-consequence-user-link"')
        ->assertSee('keeps local user '.$owner->getKey().' and its product attribution for the matched subject.')
        ->assertSeeHtml('data-testid="transition-consequence-user-retain-local"')
        ->assertSee('keeps local user '.$local->getKey().' active under standalone authority.')
        ->assertSeeHtml('data-testid="transition-consequence-invitation-retain-local"')
        ->assertSee('keeps invitation '.$invitation->getKey().' pending with stored role admin and email exit-invitation@example.test unchanged.')
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

it('refuses a corrected user email that collides with a retained invitation', function (): void {
    [$owner] = p4cConfigure(ManagedTransitionDirection::Exit);
    $invitation = p4cInvitation('retained@example.test');
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Exit);
    $mapping = static fn (string $ownerEmail): array => [
        'locals' => [
            [
                'local_kind' => 'user',
                'local_id' => (string) $owner->getKey(),
                'choice' => 'link:direct-member',
                'role' => 'owner',
                'final_email' => $ownerEmail,
            ],
            [
                'local_kind' => 'invitation',
                'local_id' => (string) $invitation->getKey(),
                'choice' => 'retain_local',
            ],
        ],
    ];

    $this->actingAsVersioned($owner)
        ->put(route('bfc.transitions.update', $transition, false), $mapping('retained@example.test'))
        ->assertSessionHasErrors('mapping');

    $this->actingAsVersioned($owner)
        ->put(route('bfc.transitions.update', $transition, false), $mapping('non-colliding@example.test'))
        ->assertRedirect(route('bfc.transitions.edit', $transition));

    expect(DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('local_kind', 'user')
        ->value('final_email'))->toBe('non-colliding@example.test');
});

it('refuses Admin, Member, and unauthenticated requests on every transition route', function (): void {
    [$owner] = p4cConfigure();
    $transition = p4cBegin($this, $owner, ManagedTransitionDirection::Adopt);
    $admin = User::query()->create(['name' => 'Route Admin', 'email' => 'route-admin@example.test']);
    $admin->forceFill(['role' => 'admin'])->save();
    $member = User::query()->create(['name' => 'Route Member', 'email' => 'route-member@example.test']);
    $member->forceFill(['role' => 'member'])->save();
    $index = route('bfc.transitions.index', ManagedTransitionDirection::Adopt->value, false);
    $store = route('bfc.transitions.store', ManagedTransitionDirection::Adopt->value, false);
    $edit = route('bfc.transitions.edit', $transition, false);
    $update = route('bfc.transitions.update', $transition, false);

    foreach ([$admin, $member] as $actor) {
        $this->actingAsVersioned($actor)->get($index)->assertForbidden();
        $this->actingAsVersioned($actor)->post($store)->assertForbidden();
        $this->actingAsVersioned($actor)->get($edit)->assertForbidden();
        $this->actingAsVersioned($actor)->put($update, ['roster' => [], 'locals' => []])->assertForbidden();
    }

    auth()->logout();
    $this->get($index)->assertRedirect(route('bfc.login'));
    $this->post($store)->assertRedirect(route('bfc.login'));
    $this->get($edit)->assertRedirect(route('bfc.login'));
    $this->put($update, ['roster' => [], 'locals' => []])->assertRedirect(route('bfc.login'));
});

it('offers adoption from members only to a standalone Owner', function (): void {
    [$owner] = p4cConfigure();
    $admin = User::query()->create(['name' => 'Entry Admin', 'email' => 'entry-admin@example.test']);
    $admin->forceFill(['role' => 'admin'])->save();

    $this->actingAsVersioned($owner)->get(route('bfc.members.index', absolute: false))
        ->assertOk()
        ->assertSeeHtml('data-testid="transition-adopt-entry"')
        ->assertSee('Adopt managed authority');
    $this->actingAsVersioned($admin)->get(route('bfc.members.index', absolute: false))
        ->assertOk()
        ->assertDontSeeHtml('data-testid="transition-adopt-entry"');
});

it('withholds the adoption entry point in managed mode', function (): void {
    [$owner] = p4cConfigure(ManagedTransitionDirection::Exit);

    $request = Request::create('/bfc/members');
    $request->setUserResolver(static fn (): User => $owner);
    $managedView = app(StandaloneMemberships::class)->index($request)
        ->with('errors', new ViewErrorBag)
        ->render();

    expect($managedView)->not->toContain('data-testid="transition-adopt-entry"');
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
        ]],
        'locals' => [
            ['local_kind' => 'user', 'local_id' => (string) $owner->getKey()],
        ],
    ])->assertRedirect();

    $this->actingAsVersioned($owner)->get(route('bfc.transitions.edit', $transition, false))
        ->assertOk()
        ->assertSee('direct-member')
        ->assertSeeHtml('<option value="defer_to_managed_jit" selected>')
        ->assertSeeHtml('data-testid="transition-consequence-roster-defer-to-managed-jit"')
        ->assertSee('subject direct-member creates no row at commit; the next managed login may still create one through managed JIT.');

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
