<x-bfc-layout :title="$manifest?->name ?? ''">
<section data-testid="ui-shell"@if ($manifest !== null) data-app-slug="{{ $manifest->slug }}"@endif class="grid gap-8">
    @if ($manifest !== null)
    <header data-testid="ui-manifest" class="grid gap-4">
        <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
            <img data-testid="ui-manifest-icon" src="{{ $manifest->icon }}" alt="{{ $manifest->name }}" class="size-16 shrink-0 object-contain sm:size-20">
            <h1 data-testid="ui-manifest-name" class="font-display text-4xl font-normal tracking-tight text-clay-ink sm:text-5xl">{{ $manifest->name }}</h1>
        </div>
        <p data-testid="ui-manifest-description" class="max-w-2xl text-lg leading-8 text-clay-soft">{{ $manifest->description }}</p>
        <a data-testid="ui-manifest-product-link" href="{{ $manifest->productUrl }}" class="bfc-link w-fit">{{ $manifest->productUrl }}</a>
    </header>
    @endif

    <nav data-testid="ui-navigation" class="bfc-nav">
        @if ($memberManagement)
            <a data-testid="ui-nav-member-management" href="{{ $memberManagementHref }}">Members</a>
        @endif
        @if ($sessionManagement)
            <a data-testid="ui-nav-session-management" href="{{ route('bfc.sessions.index') }}">Sessions</a>
        @endif
        @if ($managedTransitions)
            <a data-testid="ui-nav-managed-transitions" href="{{ route('bfc.transitions.index', $transitionDirection->value) }}">Authority</a>
        @endif
        @if ($personalCredentials)
            <a data-testid="ui-nav-personal-credentials" href="{{ route('bfc.ui.personal-credentials.index') }}">Personal credentials</a>
        @endif
        @if ($installationCredentials)
            <a data-testid="ui-nav-installation-credentials" href="{{ route('bfc.ui.installation-credentials.index') }}">Installation credentials</a>
        @endif
        <form data-testid="ui-logout-form" method="POST" action="{{ route('bfc.ui.logout') }}" class="ml-auto">
            @csrf
            <button type="submit" class="bfc-button-soft">Log out</button>
        </form>
    </nav>

    @if ($managedMemberManagement)
        <section id="managed-members" data-testid="managed-members-list" class="bfc-panel">
            <p data-testid="managed-members-incomplete" class="bfc-status">Locally materialized identities only; this is not a complete or current authority roster.</p>
            <ul class="bfc-list mt-4">
                @foreach ($managedMembers as $member)
                    <li data-testid="managed-members-item" class="bfc-row flex flex-wrap gap-x-4 gap-y-1">
                        <strong>{{ $member->name }}</strong>
                        <span>{{ $member->email }}</span>
                        <span>{{ $member->managed_membership_role }}</span>
                        <span>{{ $member->managed_membership_status }}</span>
                    </li>
                @endforeach
            </ul>
        </section>
    @endif
</section>
</x-bfc-layout>
