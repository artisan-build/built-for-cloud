<x-bfc-layout title="Loopback authorization">
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
                @if ($authorization['ownership'] === 'personal')
                    <dt>Management</dt><dd>Only the derived user can manage it; removing that user or personal subject ends it.</dd>
                @else
                    <dt>Management</dt><dd>Remaining installation members can manage it; it survives approver removal or role changes, but installation-subject removal ends it.</dd>
                @endif
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
</x-bfc-layout>
