@extends('bfc::layout')

@section('title', 'Personal credentials')

@section('content')
<section data-testid="personal-credentials">
    <h1>Personal credentials</h1>

    @isset($error)
        <section data-testid="personal-credentials-error">
            <p>{{ $error }}</p>
        </section>
    @endisset

    @if ($delivery !== null)
        <section data-testid="personal-credentials-delivery">
            <h2>Save this credential now</h2>
            <p>This delivery is shown only in this response and cannot be recovered later.</p>
            @foreach ($delivery as $label => $value)
                <p><strong>{{ $label }}</strong>: <code>{{ $value }}</code></p>
            @endforeach
            @if (($delivery['shape'] ?? null) === 'enrollment_code')
                <p>This enrollment is pending and keyless. Public-key registration is not completed here.</p>
            @endif
        </section>
    @endif

    <section data-testid="personal-credentials-issue">
        <h2>Issue a credential</h2>
        @foreach ($choices as $choice)
            <form data-testid="personal-credentials-issue-option" method="POST" action="{{ route('bfc.ui.personal-credentials.store') }}">
                @csrf
                <input type="hidden" name="app_purpose" value="{{ $choice['appPurpose'] }}">
                <input type="hidden" name="kind" value="{{ $choice['kind']->value }}">
                <p>{{ $choice['appPurpose'] }} / {{ $choice['kind']->value }}</p>
                <label>Name <input name="name"></label>
                @if ($choice['kind'] === \ArtisanBuild\BuiltForCloud\CredentialKind::Asymmetric)
                    <label>Enrollment code lifetime in seconds <input name="code_ttl_seconds" inputmode="numeric" required></label>
                @endif
                <button type="submit">Issue</button>
            </form>
        @endforeach
    </section>

    <section data-testid="personal-credentials-list">
        <h2>Your credentials</h2>
        <ul>
            @foreach ($credentials as $credential)
                <li data-testid="personal-credentials-item">
                    <strong>{{ $credential->name ?? $credential->id }}</strong>
                    <span>{{ $credential->kind->value }}</span>
                    <span>{{ $credential->purpose?->value }}</span>
                    <span>{{ $credential->status }}</span>
                    <form method="POST" action="{{ route('bfc.ui.personal-credentials.rotate', $credential->id) }}">
                        @csrf
                        @if ($credential->kind === \ArtisanBuild\BuiltForCloud\CredentialKind::Asymmetric)
                            <label>Enrollment code lifetime in seconds <input name="code_ttl_seconds" inputmode="numeric" required></label>
                        @endif
                        <button type="submit">Rotate</button>
                    </form>
                    <form method="POST" action="{{ route('bfc.ui.personal-credentials.destroy', $credential->id) }}">
                        @csrf
                        @method('DELETE')
                        <button type="submit">Revoke</button>
                    </form>
                </li>
            @endforeach
        </ul>
    </section>
</section>
@endsection
