@extends('bfc::layout')

@section('title', 'Reset password')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="password-request-form">
    <div class="bfc-panel">
        <div class="bfc-kicker">Account recovery</div>
        <h1>Reset password</h1>
        @if (session('status'))
            <p class="bfc-status" data-testid="password-request-status">{{ session('status') }}</p>
        @endif
        <form method="POST" action="{{ route('bfc.password.email') }}">
            @csrf
            <label>Email <input name="email" type="email" autocomplete="email" required></label>
            <button type="submit">Send reset link</button>
        </form>
    </div>
</section>
@endsection
