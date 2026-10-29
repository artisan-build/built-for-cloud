{{-- The configured Layout component owns this shell. Keep app assets in the
     head/scripts stacks and app navigation in the sidebar slot. The one
     sidebar is a native popover on mobile and a sticky column from lg. --}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#faf3e8">
    <title>{{ $title }}</title>
    <link rel="icon" href="{{ $manifest->imageUrl() }}">
    @if ($stylesheetUrl)
        <link rel="stylesheet" href="{{ $stylesheetUrl }}">
    @endif
    @stack('head')
</head>
<body data-testid="bfc-layout"
      class="bfc-body min-h-screen bg-clay-paper font-sans text-clay-soft antialiased
             [--color-white:var(--color-clay-surface)] [--color-zinc-50:var(--color-clay-surface)] [--color-zinc-100:var(--color-clay-slip)] [--color-zinc-200:var(--color-clay-sand)] [--color-zinc-300:var(--color-clay-edge)] [--color-zinc-400:var(--color-clay-dot)] [--color-zinc-500:var(--color-clay-brown)] [--color-zinc-600:var(--color-clay-soft)] [--color-zinc-700:var(--color-clay-soft)] [--color-zinc-800:var(--color-clay-ink)] [--color-zinc-900:var(--color-clay-ink)] [--color-zinc-950:var(--color-clay-ink)] [--color-accent:var(--color-clay-brown)] [--color-accent-content:var(--color-clay-iron)] [--color-accent-foreground:var(--color-clay-surface)]">
    <a href="#main-content" class="bfc-skip-link">Skip to content</a>

    <aside id="bfc-navigation"
           popover="auto"
           aria-label="Application navigation"
           data-testid="bfc-sidebar"
           class="bfc-sidebar">
        <div data-testid="bfc-mobile-drawer" class="bfc-sidebar-content">
            <div class="flex items-center justify-between gap-3">
                <a href="{{ \ArtisanBuild\BuiltForCloud\View\Layout::SCALPELS_URL }}"
                   data-testid="bfc-header-scalpels"
                   class="bfc-wordmark">
                    <img src="{{ $wordmarkUrl }}" alt="Scalpels dashboard" width="480" height="138">
                </a>
                <button type="button"
                        popovertarget="bfc-navigation"
                        popovertargetaction="hide"
                        data-testid="bfc-mobile-drawer-close"
                        class="bfc-shell-control lg:hidden"
                        aria-label="Close navigation">
                    <span aria-hidden="true">&#215;</span>
                </button>
            </div>

            <nav aria-label="Scalpels" class="bfc-sidebar-links">
                <a href="{{ url('/') }}"
                   data-testid="bfc-header-app"
                   class="bfc-shell-link">
                    <img src="{{ $manifest->imageUrl() }}" alt="" class="size-6 shrink-0 object-contain">
                    <span class="truncate">{{ $manifest->name }}</span>
                </a>
                <a href="{{ \ArtisanBuild\BuiltForCloud\View\Layout::SCALPELS_DOCS_URL }}"
                   data-testid="bfc-header-docs"
                   class="bfc-shell-link">
                    Documentation
                </a>
            </nav>

            @isset($sidebar)
                <div data-testid="bfc-sidebar-slot" class="bfc-sidebar-slot">{{ $sidebar }}</div>
            @else
                <div data-testid="bfc-sidebar-fallback" class="bfc-sidebar-slot">
                    <span class="text-sm text-clay-muted">Application navigation</span>
                </div>
            @endisset

            @if ($user)
                <footer data-testid="bfc-sidebar-user" class="bfc-sidebar-user">
                    <button type="button"
                            popovertarget="bfc-user-menu"
                            data-testid="bfc-user-menu-button"
                            class="bfc-shell-control bfc-desktop-user-button">
                        <span class="truncate">{{ $user->name }}</span>
                        <span aria-hidden="true">&#8963;</span>
                    </button>
                </footer>
            @endif
        </div>
    </aside>

    <header data-testid="bfc-mobile-header" class="bfc-mobile-header">
        <button type="button"
                popovertarget="bfc-navigation"
                popovertargetaction="show"
                data-testid="bfc-mobile-drawer-open"
                class="bfc-shell-control"
                aria-label="Open navigation">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="size-5" aria-hidden="true">
                <path stroke-linecap="round" d="M4 7h16M4 12h16M4 17h16" />
            </svg>
        </button>
        <a href="{{ url('/') }}" class="bfc-shell-link min-w-0">
            <img src="{{ $manifest->imageUrl() }}" alt="" class="size-6 shrink-0 object-contain">
            <span class="truncate">{{ $manifest->name }}</span>
        </a>
        @if ($user)
            <button type="button"
                    popovertarget="bfc-user-menu"
                    data-testid="bfc-mobile-user-menu-button"
                    class="bfc-shell-control bfc-mobile-user-button">
                <span class="truncate">{{ $user->name }}</span>
            </button>
        @endif
    </header>

    <main>
        <div id="main-content" data-testid="bfc-main" class="bfc-main" tabindex="-1">
            {{ $slot }}
        </div>
    </main>

    @if ($user)
        @include('bfc::shell.user-menu')
    @endif

    @stack('scripts')
</body>
</html>
