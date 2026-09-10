@extends('bfc::layout')

@section('title', 'Members')

@push('head')
    @include('bfc::auth.styles')
@endpush

@section('content')
<section class="bfc-auth" data-testid="members-management">
    <div class="bfc-panel">
        <div class="bfc-kicker">Installation access</div>
        <h1>Members</h1>
        @if (session('status'))
            <p class="bfc-status" data-testid="members-status">{{ session('status') }}</p>
        @endif
        @if ($errors->any())
            <p class="bfc-error" data-testid="members-errors">{{ $errors->first() }}</p>
        @endif

        @if (\ArtisanBuild\BuiltForCloud\RolePolicy::canManageMembers($actor?->role))
            <form method="POST" action="{{ route('bfc.members.invitations.store') }}" data-testid="members-invitation-form">
                @csrf
                <label>Email <input name="email" type="email" required></label>
                <label>Role
                    <select name="role">
                        <option value="member">Member</option>
                        @if ($actor?->role === 'owner')<option value="admin">Admin</option>@endif
                    </select>
                </label>
                <button type="submit">Invite</button>
            </form>
        @endif

        <ul class="bfc-list" data-testid="members-list">
            @foreach ($members as $member)
                <li class="bfc-row" data-testid="members-item">
                    <strong>{{ $member->name }}</strong> <span>{{ $member->email }}</span>
                    <div>{{ $member->role }} / {{ $member->status }}</div>
                    @if ($member->status === 'active' && $member->role !== 'owner' && \ArtisanBuild\BuiltForCloud\RolePolicy::canManage($actor?->role, $member->role))
                        <div class="bfc-actions">
                            @if ($actor?->role === 'owner')
                                <form method="POST" action="{{ route('bfc.members.role.update', $member) }}">
                                    @csrf
                                    @method('PUT')
                                    <input type="hidden" name="role" value="{{ $member->role === 'admin' ? 'member' : 'admin' }}">
                                    <button type="submit">Change role</button>
                                </form>
                            @endif
                            <form method="POST" action="{{ route('bfc.members.destroy', $member) }}">
                                @csrf
                                @method('DELETE')
                                <button type="submit">Deactivate</button>
                            </form>
                        </div>
                    @endif
                </li>
            @endforeach
        </ul>

        @if ($invitations->isNotEmpty())
            <ul class="bfc-list" data-testid="members-pending-invitations">
                @foreach ($invitations as $invitation)
                    <li data-testid="members-pending-item">{{ $invitation->email }} / {{ $invitation->role }}</li>
                @endforeach
            </ul>
        @endif
    </div>
</section>
@endsection
