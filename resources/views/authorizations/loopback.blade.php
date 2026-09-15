@extends('bfc::layout')

@section('title', 'Loopback authorization')

@section('content')
<section data-testid="device-authorization-loopback">
    @if ($outcome === 'unavailable')
        <div data-testid="device-authorization-unavailable">This authorization is unavailable.</div>
    @elseif ($outcome === 'retry')
        <div data-testid="device-authorization-retry">The authorization service is temporarily unavailable.</div>
    @elseif ($authorization !== null)
        <article data-testid="device-authorization-profile">
            <dl>
                <dt>Application purpose</dt><dd>{{ $authorization['appPurpose'] }}</dd>
                <dt>Audience</dt><dd>{{ $authorization['audience'] }}</dd>
                <dt>Installation</dt><dd>{{ $authorization['installation'] }}</dd>
                <dt>Application</dt><dd>{{ $authorization['application'] }}</dd>
                <dt>Ownership</dt><dd>{{ $authorization['ownership'] }}</dd>
                <dt>Callback</dt><dd>{{ $authorization['callbackAuthority'] }}</dd>
                @if ($authorization['label'] !== null)
                    <dt>Label</dt><dd>{{ $authorization['label'] }}</dd>
                @endif
            </dl>
            <div data-testid="device-authorization-actions">
                <form method="POST" action="{{ route('bfc.loopback.decide') }}">
                    @csrf
                    <input type="hidden" name="action" value="approve">
                    <input type="hidden" name="submission_nonce" value="{{ $authorization['approveNonce'] }}">
                    <button type="submit">Approve</button>
                </form>
                <form method="POST" action="{{ route('bfc.loopback.decide') }}">
                    @csrf
                    <input type="hidden" name="action" value="deny">
                    <input type="hidden" name="submission_nonce" value="{{ $authorization['denyNonce'] }}">
                    <button type="submit">Deny</button>
                </form>
            </div>
        </article>
    @endif
</section>
@endsection
