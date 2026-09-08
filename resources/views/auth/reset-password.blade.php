@extends('bfc::layout')

@section('title', 'Choose password')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="password-reset-form">
    <div class="bfc-panel">
        <div class="bfc-kicker">Account recovery</div>
        <h1>Choose a password</h1>
        @if ($errors->any())
            <p class="bfc-error" data-testid="password-reset-errors">{{ $errors->first() }}</p>
        @endif
        <form method="POST" action="{{ route('bfc.password.update') }}">
            @csrf
            <input type="hidden" name="token" value="{{ $token }}">
            <label>Email <input name="email" type="email" autocomplete="email" value="{{ $email }}" required></label>
            <label>New password <input name="password" type="password" autocomplete="new-password" required></label>
            <label>Confirm password <input name="password_confirmation" type="password" autocomplete="new-password" required></label>
            <button type="submit">Reset password</button>
        </form>
    </div>
</section>
@endsection
