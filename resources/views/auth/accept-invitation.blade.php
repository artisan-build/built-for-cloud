@extends('bfc::layout')

@section('title', 'Accept invitation')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="invitation-accept-form">
    <div class="bfc-panel">
        <div class="bfc-kicker">Membership</div>
        <h1>Accept invitation</h1>
        @if ($errors->any())
            <p class="bfc-error" data-testid="invitation-accept-errors">{{ $errors->first() }}</p>
        @endif
        <form method="POST" action="{{ route('bfc.invitations.accept.store') }}">
            @csrf
            <input type="hidden" name="token" value="{{ $token }}">
            @if ($intended)
                <input type="hidden" name="intended" value="{{ $intended }}">
            @endif
            <label>Email <input type="email" value="{{ $email }}" disabled></label>
            <label>Name <input name="name" autocomplete="name" required></label>
            <label>Password <input name="password" type="password" autocomplete="new-password" required></label>
            <label>Confirm password <input name="password_confirmation" type="password" autocomplete="new-password" required></label>
            <button type="submit">Create account</button>
        </form>
    </div>
</section>
@endsection
