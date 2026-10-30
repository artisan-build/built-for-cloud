<div id="bfc-user-menu" popover data-testid="bfc-user-menu" class="bfc-user-menu">
    <div class="grid px-2 py-1.5 text-start text-sm leading-tight">
        <span class="truncate font-medium text-clay-ink">{{ $user->name }}</span>
        <span class="truncate text-clay-muted">{{ $user->email }}</span>
    </div>
    <hr class="bfc-user-menu-separator">
    <a href="{{ $scalpelsUrl }}" class="bfc-user-menu-item">
        Scalpels dashboard
    </a>
    <a href="{{ $scalpelsDocsUrl }}" class="bfc-user-menu-item lg:hidden">
        Documentation
    </a>
    @if ($logoutUrl)
        <hr class="bfc-user-menu-separator">
        <form method="POST" action="{{ $logoutUrl }}" data-testid="bfc-user-menu-logout">
            @csrf
            <button type="submit" class="bfc-user-menu-item">Log out</button>
        </form>
    @endif
</div>
