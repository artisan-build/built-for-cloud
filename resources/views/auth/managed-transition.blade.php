@extends('bfc::layout')

@section('title', ucfirst($direction->value).' authority')

@push('head')
    @include('bfc::auth.styles')
    <style>
        .bfc-transition { width: min(72rem, calc(100% - 2rem)); }
        .bfc-transition-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 25rem), 1fr)); gap: 1rem; }
        .bfc-transition-card { border: 1px solid #d8d2c5; border-radius: .75rem; padding: 1rem; background: #fff; }
        .bfc-transition-meta { color: #5d675f; font-size: .9rem; overflow-wrap: anywhere; }
        .bfc-transition-fixed { border-left: .25rem solid #a54824; padding: .75rem 1rem; background: #fbefe8; }
        .bfc-transition-controls { display: grid; gap: .5rem; margin-top: 1rem; }
    </style>
@endpush

@section('content')
<section class="bfc-auth bfc-transition" data-testid="transition-proposal">
    <div class="bfc-panel">
        <div class="bfc-kicker">Authority transition</div>
        <h1>{{ $direction === \ArtisanBuild\BuiltForCloud\ManagedTransitionDirection::Adopt ? 'Adopt managed authority' : 'Exit managed authority' }}</h1>

        @if (session('status'))
            <p class="bfc-status" data-testid="transition-status">{{ session('status') }}</p>
        @endif
        @if ($errors->any())
            <p class="bfc-error" data-testid="transition-errors">{{ $errors->first() }}</p>
        @endif

        @if (! $transition)
            <section data-testid="transition-preparation">
                <p>This prepares a complete authority roster and local identity proposal for review.</p>
                @if ($affordanceEnabled)
                    <form method="POST" action="{{ route('bfc.transitions.store', $direction->value) }}">
                        @csrf
                        <button type="submit">Prepare proposal</button>
                    </form>
                @else
                    <p class="bfc-transition-meta">This app has not enabled the transition preparation button.</p>
                @endif
            </section>
        @else
            @php
                $localOptions = $users->map(fn ($user) => ['ref' => 'user:'.$user->getKey(), 'label' => 'User '.$user->getKey().' — '.$user->email])
                    ->concat($invitations->map(fn ($invitation) => ['ref' => 'invitation:'.$invitation->getKey(), 'label' => 'Invitation '.$invitation->getKey().' — '.$invitation->email]));
            @endphp

            @if ($direction === \ArtisanBuild\BuiltForCloud\ManagedTransitionDirection::Adopt)
                <p class="bfc-transition-fixed" data-testid="transition-adopt-authority-fixed">Roles and membership come from the Team Account authority. You can correct local matches, commit timing, and final local emails; authority roles are not editable here.</p>
            @else
                <p>Standalone roles and final local emails are editable because no external authority persists after exit.</p>
            @endif

            <form method="POST" action="{{ route('bfc.transitions.update', $transition) }}">
                @csrf
                @method('PUT')
                <fieldset @disabled(! $affordanceEnabled) style="border: 0; margin: 0; padding: 0;">

                <section data-testid="transition-roster">
                    <h2>Authority roster</h2>
                    <div class="bfc-transition-grid">
                        @forelse ($roster as $index => $member)
                            @php
                                $mapping = $mappingsBySubject->get($member->scalpels_id);
                                $localRef = $mapping && $mapping->local_id ? $mapping->local_kind.':'.$mapping->local_id : '';
                                $linkedUser = $mapping?->local_kind === 'user' ? $users->firstWhere('id', $mapping->local_id) : null;
                                $linkedInvitation = $mapping?->local_kind === 'invitation' ? $invitations->firstWhere('id', $mapping->local_id) : null;
                                $emailProvenance = $linkedUser && $mapping?->final_email === $linkedUser->email
                                    ? ($linkedUser->email_is_generated ? 'generated' : 'local-contact')
                                    : ($linkedInvitation && $mapping?->final_email === $linkedInvitation->email
                                        ? 'invitation-contact'
                                        : ($mapping?->disposition === 'create' && $mapping?->final_email === $member->contact_email
                                             ? 'authority-contact'
                                             : 'owner-corrected'));
                                $emailProvenanceLabel = match ($emailProvenance) {
                                    'generated' => 'generated local address',
                                    'local-contact' => 'current local contact',
                                    'invitation-contact' => 'stored invitee contact',
                                    'authority-contact' => 'authority contact',
                                    default => 'Owner-corrected local address',
                                };
                            @endphp
                            <article class="bfc-transition-card" data-testid="transition-roster-member">
                                <strong>{{ $member->display_name }}</strong>
                                <div class="bfc-transition-meta">scalpels_id: {{ $member->scalpels_id }}</div>
                                <div>Authority role: <strong>{{ $member->role }}</strong></div>
                                <div>Contact email: {{ $member->contact_email }} (authority contact)</div>

                                @if ($direction === \ArtisanBuild\BuiltForCloud\ManagedTransitionDirection::Adopt)
                                    <input type="hidden" name="roster[{{ $index }}][scalpels_id]" value="{{ $member->scalpels_id }}">
                                    <div class="bfc-transition-controls">
                                        <label>Match and commit disposition
                                            <select name="roster[{{ $index }}][choice]" data-testid="transition-match-control">
                                                <option value="create" @selected($mapping?->disposition === 'create')>Create at commit</option>
                                                <option value="defer_to_managed_jit" @selected($mapping?->disposition === 'defer_to_managed_jit')>Let managed login create later</option>
                                                @foreach ($localOptions as $option)
                                                    <option value="link:{{ $option['ref'] }}" @selected($localRef === $option['ref'])>Link {{ $option['label'] }}</option>
                                                @endforeach
                                            </select>
                                        </label>
                                        @if (in_array($mapping?->disposition, ['link', 'create'], true))
                                            <label>Final local email
                                                <input name="roster[{{ $index }}][final_email]" type="email" value="{{ $mapping?->final_email }}" required data-testid="transition-email-control">
                                            </label>
                                            <div class="bfc-transition-meta" data-testid="transition-email-provenance-{{ $emailProvenance }}">
                                                Final email {{ $mapping?->final_email }} provenance: {{ $emailProvenanceLabel }}
                                            </div>
                                        @endif
                                    </div>
                                    <p data-testid="transition-consequence-roster-{{ str_replace('_', '-', $mapping?->disposition ?? 'unknown') }}"><strong>Consequence:</strong>
                                        @if ($mapping?->disposition === 'link')
                                            subject {{ $member->scalpels_id }} keeps {{ $mapping->local_kind }} {{ $mapping->local_id }} and its attribution.
                                        @elseif ($mapping?->disposition === 'create')
                                            subject {{ $member->scalpels_id }} creates a local user at commit with authority contact {{ $mapping->final_email }}.
                                        @else
                                            subject {{ $member->scalpels_id }} creates no row at commit; the next managed login may still create one through managed JIT.
                                        @endif
                                    </p>
                                @elseif (! $mapping)
                                    <p class="bfc-transition-fixed" data-testid="transition-roster-informational"><strong>Not carried into standalone.</strong> Roster subject {{ $member->scalpels_id }} ({{ $member->contact_email }}) has no local identity, so no mapping element is sent to stage.</p>
                                @else
                                    <p><strong>Proposed match:</strong> {{ $mapping->local_kind }} {{ $mapping->local_id }}</p>
                                @endif
                            </article>
                        @empty
                            <p>No authority roster members were returned.</p>
                        @endforelse
                    </div>
                </section>

                <section data-testid="transition-locals">
                    <h2>Local identities</h2>
                    <div class="bfc-transition-grid">
                        @foreach ($users as $index => $user)
                            @php
                                $mapping = $mappingsByLocal->get('user:'.$user->getKey());
                                $emailProvenance = $mapping?->final_email === $user->email
                                    ? ($user->email_is_generated ? 'generated' : 'local-contact')
                                    : 'owner-corrected';
                                $emailProvenanceLabel = match ($emailProvenance) {
                                    'generated' => 'generated local address',
                                    'local-contact' => 'current local contact',
                                    default => 'Owner-corrected local address',
                                };
                            @endphp
                            <article class="bfc-transition-card" data-testid="transition-local-user">
                                <strong>{{ $user->name }}</strong>
                                <div class="bfc-transition-meta">local_kind: user / local_id: {{ $user->getKey() }}</div>
                                <div>Current email: {{ $user->email }} ({{ $user->email_is_generated ? 'generated local address' : 'local contact address' }})</div>
                                @if ($user->original_contact_email)
                                    <div>Original contact: {{ $user->original_contact_email }}</div>
                                @endif
                                @if ($user->email_conflict_at && $user->email_conflict_source)
                                    <p class="bfc-error" data-testid="transition-email-conflict">Renewed contact conflict: {{ $user->email_conflict_source }}</p>
                                @endif

                                <input type="hidden" name="locals[user-{{ $index }}][local_kind]" value="user">
                                <input type="hidden" name="locals[user-{{ $index }}][local_id]" value="{{ $user->getKey() }}">

                                @if ($direction === \ArtisanBuild\BuiltForCloud\ManagedTransitionDirection::Exit)
                                    <div class="bfc-transition-controls">
                                        <label>Match and disposition
                                            <select name="locals[user-{{ $index }}][choice]" data-testid="transition-match-control">
                                                <option value="retain_local" @selected($mapping?->disposition === 'retain_local')>Retain locally</option>
                                                <option value="exclude" @selected($mapping?->disposition === 'exclude')>Deactivate</option>
                                                @foreach ($roster as $member)
                                                    <option value="link:{{ $member->scalpels_id }}" @selected($mapping?->scalpels_id === $member->scalpels_id)>Link {{ $member->display_name }} — {{ $member->scalpels_id }}</option>
                                                @endforeach
                                            </select>
                                        </label>
                                        @if (in_array($mapping?->disposition, ['link', 'retain_local'], true))
                                            <label>Standalone role
                                                <select name="locals[user-{{ $index }}][role]" data-testid="transition-role-control">
                                                    @foreach (['owner', 'admin', 'member'] as $role)
                                                        <option value="{{ $role }}" @selected($mapping?->role === $role)>{{ ucfirst($role) }}</option>
                                                    @endforeach
                                                </select>
                                            </label>
                                            <label>Final local email
                                                <input name="locals[user-{{ $index }}][final_email]" type="email" value="{{ $mapping?->final_email }}" required data-testid="transition-email-control">
                                            </label>
                                            <div class="bfc-transition-meta" data-testid="transition-email-provenance-{{ $emailProvenance }}">
                                                Final email {{ $mapping?->final_email }} provenance: {{ $emailProvenanceLabel }}
                                            </div>
                                        @endif
                                    </div>
                                @endif
                                <p data-testid="transition-consequence-user-{{ str_replace('_', '-', $mapping?->disposition ?? 'unknown') }}"><strong>Consequence:</strong>
                                    @if ($mapping?->disposition === 'link')
                                        keeps local user {{ $user->getKey() }} and its product attribution for the matched subject.
                                    @elseif ($mapping?->disposition === 'retain_local')
                                        keeps local user {{ $user->getKey() }} active under standalone authority.
                                    @else
                                        deactivates this user without deleting local ID {{ $user->getKey() }} or its attribution.
                                    @endif
                                </p>
                            </article>
                        @endforeach

                        @foreach ($invitations as $index => $invitation)
                            @php($mapping = $mappingsByLocal->get('invitation:'.$invitation->getKey()))
                            <article class="bfc-transition-card" data-testid="transition-local-invitation">
                                <strong>Pending invitation</strong>
                                <div class="bfc-transition-meta">local_kind: invitation / local_id: {{ $invitation->getKey() }}</div>
                                <div>Invitee email: {{ $invitation->email }}</div>
                                <div>Invited role: {{ $invitation->role }}</div>
                                <input type="hidden" name="locals[invitation-{{ $index }}][local_kind]" value="invitation">
                                <input type="hidden" name="locals[invitation-{{ $index }}][local_id]" value="{{ $invitation->getKey() }}">

                                @if ($direction === \ArtisanBuild\BuiltForCloud\ManagedTransitionDirection::Exit)
                                    <div class="bfc-transition-controls">
                                        <label>Match and disposition
                                            <select name="locals[invitation-{{ $index }}][choice]" data-testid="transition-match-control">
                                                <option value="retain_local" @selected($mapping?->disposition === 'retain_local')>Keep pending</option>
                                                <option value="exclude" @selected($mapping?->disposition === 'exclude')>Cancel invitation</option>
                                                @foreach ($roster as $member)
                                                    <option value="link:{{ $member->scalpels_id }}" @selected($mapping?->scalpels_id === $member->scalpels_id)>Link {{ $member->display_name }} — {{ $member->scalpels_id }}</option>
                                                @endforeach
                                            </select>
                                        </label>
                                        @if ($mapping?->disposition === 'link')
                                            <label>Standalone role
                                                <select name="locals[invitation-{{ $index }}][role]" data-testid="transition-role-control">
                                                    @foreach (['owner', 'admin', 'member'] as $role)
                                                        <option value="{{ $role }}" @selected($mapping?->role === $role)>{{ ucfirst($role) }}</option>
                                                    @endforeach
                                                </select>
                                            </label>
                                            <label>Final local email
                                                <input name="locals[invitation-{{ $index }}][final_email]" type="email" value="{{ $mapping?->final_email }}" required data-testid="transition-email-control">
                                            </label>
                                            <div class="bfc-transition-meta" data-testid="transition-email-provenance-{{ $mapping?->final_email === $invitation->email ? 'invitation-contact' : 'owner-corrected' }}">
                                                Final email {{ $mapping?->final_email }} provenance: {{ $mapping?->final_email === $invitation->email ? 'stored invitee contact' : 'Owner-corrected local address' }}
                                            </div>
                                        @elseif ($mapping?->disposition === 'retain_local')
                                            <p class="bfc-transition-fixed" data-testid="transition-invitation-fixed">Invitation {{ $invitation->getKey() }} remains pending with stored invitee email {{ $invitation->email }} and invited role {{ $invitation->role }}; neither field is editable.</p>
                                        @endif
                                    </div>
                                @endif
                                <p data-testid="transition-consequence-invitation-{{ str_replace('_', '-', $mapping?->disposition ?? 'unknown') }}"><strong>Consequence:</strong>
                                    @if ($mapping?->disposition === 'link')
                                        invitation {{ $invitation->getKey() }} creates a user for the matched subject and is consumed as accepted.
                                    @elseif ($mapping?->disposition === 'retain_local')
                                        keeps invitation {{ $invitation->getKey() }} pending with stored role {{ $invitation->role }} and email {{ $invitation->email }} unchanged.
                                    @else
                                        cancels invitation {{ $invitation->getKey() }} without creating or deleting a user row.
                                    @endif
                                </p>
                            </article>
                        @endforeach
                    </div>
                </section>
                </fieldset>

                @if ($affordanceEnabled)
                    <p><button type="submit" data-testid="transition-save-control">Save corrections</button></p>
                @else
                    <p class="bfc-transition-meta">This app has not enabled proposal correction controls. Direct requests remain fully enforced.</p>
                @endif
            </form>
            @if ($affordanceEnabled)
                <form method="POST" action="{{ route('bfc.transitions.complete', $transition) }}">
                    @csrf
                    <button type="submit" data-testid="transition-complete-control">Commit and switch authority</button>
                </form>
            @endif
        @endif
    </div>
</section>
@endsection
