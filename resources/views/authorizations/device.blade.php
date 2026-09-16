@extends('bfc::layout')

@section('title', 'Device authorization')

@section('content')
<section data-testid="device-authorization-page">
    @if ($outcome === 'unavailable')
        <div data-testid="device-authorization-unavailable">This authorization is unavailable.</div>
    @elseif ($outcome === 'retry')
        <div data-testid="device-authorization-retry">The authorization service is temporarily unavailable.</div>
    @elseif ($outcome !== null)
        <div data-testid="device-authorization-result">{{ $outcome }}</div>
    @else
        <div data-testid="device-authorization-list">
            @foreach ($authorizations as $authorization)
                <article data-testid="device-authorization-profile">
                    <dl>
                        <dt>Code</dt><dd>{{ $authorization['userCode'] }}</dd>
                        <dt>Application purpose</dt><dd>{{ $authorization['appPurpose'] }}</dd>
                        <dt>Audience</dt><dd>{{ $authorization['audience'] }}</dd>
                        <dt>Installation</dt><dd>{{ $authorization['installation'] }}</dd>
                        <dt>Application</dt><dd>{{ $authorization['application'] }}</dd>
                        <dt>Ownership</dt><dd>{{ $authorization['ownership'] }}</dd>
                        @if ($authorization['ownership'] === 'personal')
                            <dt>Management</dt><dd>Only the derived user can manage it; removing that user or personal subject ends it.</dd>
                        @else
                            <dt>Management</dt><dd>Remaining installation members can manage it; it survives approver removal or role changes, but installation-subject removal ends it.</dd>
                        @endif
                        @if ($authorization['label'] !== null)
                            <dt>Label</dt><dd>{{ $authorization['label'] }}</dd>
                        @endif
                    </dl>
                    <div data-testid="device-authorization-actions">
                        <form method="POST" action="{{ route('bfc.device.decide') }}">
                            @csrf
                            <input type="hidden" name="user_code" value="{{ $authorization['userCode'] }}">
                            <input type="hidden" name="action" value="approve">
                            <input type="hidden" name="submission_nonce" value="{{ $authorization['approveNonce'] }}">
                            <button type="submit">Approve</button>
                        </form>
                        <form method="POST" action="{{ route('bfc.device.decide') }}">
                            @csrf
                            <input type="hidden" name="user_code" value="{{ $authorization['userCode'] }}">
                            <input type="hidden" name="action" value="deny">
                            <input type="hidden" name="submission_nonce" value="{{ $authorization['denyNonce'] }}">
                            <button type="submit">Deny</button>
                        </form>
                    </div>
                </article>
            @endforeach
        </div>
    @endif
</section>
@endsection
