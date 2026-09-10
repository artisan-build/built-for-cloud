@extends('bfc::layout')

@section('title', 'Sign in')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="login-form">
    <div class="bfc-panel">
        <div class="bfc-kicker">Built for Cloud</div>
        <h1>Sign in</h1>
        @if ($errors->any())
            <p class="bfc-error" data-testid="login-errors">{{ $errors->first() }}</p>
        @endif
        <form method="POST" action="{{ route('bfc.login.store') }}">
            @csrf
            @if ($intended)
                <input type="hidden" name="intended" value="{{ $intended }}">
            @endif
            <label>Email <input name="email" type="email" autocomplete="email" value="{{ old('email') }}" required></label>
            <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
            <button type="submit">Sign in</button>
        </form>
        <p><a class="bfc-link" href="{{ route('bfc.password.request') }}">Forgot your password?</a></p>
    </div>
</section>
@endsection
