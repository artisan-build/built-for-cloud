@extends('bfc::layout')

@section('title')
@if ($manifest !== null){{ $manifest->name }}@endif
@endsection

@section('content')
<section data-testid="ui-shell"@if ($manifest !== null) data-app-slug="{{ $manifest->slug }}"@endif>
    @if ($manifest !== null)
    <header data-testid="ui-manifest">
        <img data-testid="ui-manifest-icon" src="{{ $manifest->icon }}" alt="{{ $manifest->name }}">
        <h1 data-testid="ui-manifest-name">{{ $manifest->name }}</h1>
        <p data-testid="ui-manifest-description">{{ $manifest->description }}</p>
        <a data-testid="ui-manifest-product-link" href="{{ $manifest->productUrl }}">{{ $manifest->productUrl }}</a>
    </header>
    @endif

    <nav data-testid="ui-navigation">
        @if ($memberManagement)
            <a data-testid="ui-nav-member-management" href="{{ route('bfc.members.index') }}">Members</a>
        @endif
        @if ($sessionManagement)
            <a data-testid="ui-nav-session-management" href="{{ route('bfc.sessions.index') }}">Sessions</a>
        @endif
        @if ($managedTransitions)
            <a data-testid="ui-nav-managed-transitions" href="{{ route('bfc.transitions.index', $transitionDirection->value) }}">Authority</a>
        @endif
        @if ($personalCredentials)
            <a data-testid="ui-nav-personal-credentials" href="{{ url('/bfc/ui/credentials/personal') }}">Personal credentials</a>
        @endif
        @if ($installationCredentials)
            <a data-testid="ui-nav-installation-credentials" href="{{ url('/bfc/ui/credentials/installation') }}">Installation credentials</a>
        @endif
    </nav>
</section>
@endsection
