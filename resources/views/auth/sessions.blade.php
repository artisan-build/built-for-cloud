@extends('bfc::layout')

@section('title', 'Sessions')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="sessions-management">
    <div class="bfc-panel">
        <div class="bfc-kicker">Account security</div>
        <h1>Sessions</h1>
        @if (session('status'))
            <p class="bfc-status" data-testid="sessions-status">{{ session('status') }}</p>
        @endif
        @if ($errors->any())
            <p class="bfc-error" data-testid="sessions-errors">{{ $errors->first() }}</p>
        @endif

        @if (! $enumerable)
            <p data-testid="sessions-unavailable">This session driver cannot enumerate account sessions.</p>
        @else
            <ul class="bfc-list" data-testid="sessions-list">
                @foreach ($sessions as $session)
                    <li class="bfc-row" data-testid="sessions-item">
                        <span>{{ $session->ip_address ?: 'unknown' }}</span>
                        <span>{{ $session->user_agent ?: 'unknown' }}</span>
                        @if (hash_equals($currentSessionId, (string) $session->id))
                            <strong data-testid="sessions-current">Current</strong>
                        @else
                            <form method="POST" action="{{ route('bfc.sessions.destroy', $session->id) }}">
                                @csrf
                                @method('DELETE')
                                <label>Current password <input name="password" type="password" autocomplete="current-password" required></label>
                                <button type="submit">Revoke session</button>
                            </form>
                        @endif
                    </li>
                @endforeach
            </ul>
            <form method="POST" action="{{ route('bfc.sessions.destroy-others') }}" data-testid="sessions-revoke-others-form">
                @csrf
                @method('DELETE')
                <label>Current password <input name="password" type="password" autocomplete="current-password" required></label>
                <button type="submit">Revoke other sessions</button>
            </form>
        @endif
    </div>
</section>
@endsection
