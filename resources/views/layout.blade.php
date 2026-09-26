{{--
    The default Built for Cloud shell, rendered by
    ArtisanBuild\BuiltForCloud\View\Layout for `<x-bfc-layout>` and for every
    full-page Livewire component. It wears Scalpels' light clay theme, so
    the apps in the fleet read as one product.

    The layout is chosen by configuration rather than by editing this
    file: an app that wants a different shell names its own Component
    class in BUILT_FOR_CLOUD_LAYOUT. Pages add their own assets to the
    `head` and `scripts` stacks.

    The header carries the Scalpels wordmark and the app's own name and
    icon. An app that declares no manifest has not said it is a Scalpels
    app, so its shell stays unbranded: no header at all.

    The body maps Flux's zinc and accent palette onto clay, as Scalpels'
    own shell does, so Flux controls on an app's full-page Livewire screens
    take the theme without being edited.
--}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#faf3e8">
    <title>{{ $title }}</title>
    @if ($manifest)
        <link rel="icon" href="{{ $manifest->imageUrl() }}">
    @endif
    @if ($stylesheetUrl)
        <link rel="stylesheet" href="{{ $stylesheetUrl }}">
    @endif
    @stack('head')
</head>
<body data-testid="bfc-layout"
      class="bfc-body min-h-screen bg-clay-paper font-sans text-clay-soft antialiased
             [--color-white:var(--color-clay-surface)] [--color-zinc-50:var(--color-clay-surface)] [--color-zinc-100:var(--color-clay-slip)] [--color-zinc-200:var(--color-clay-sand)] [--color-zinc-300:var(--color-clay-edge)] [--color-zinc-400:var(--color-clay-dot)] [--color-zinc-500:var(--color-clay-brown)] [--color-zinc-600:var(--color-clay-soft)] [--color-zinc-700:var(--color-clay-soft)] [--color-zinc-800:var(--color-clay-ink)] [--color-zinc-900:var(--color-clay-ink)] [--color-zinc-950:var(--color-clay-ink)] [--color-accent:var(--color-clay-brown)] [--color-accent-content:var(--color-clay-iron)] [--color-accent-foreground:var(--color-clay-surface)]">
    @if ($manifest)
        <header data-testid="bfc-header"
                class="sticky top-0 z-50 bg-clay-paper/80 px-5 text-clay-ink backdrop-blur-md
                       sm:px-8">
            <div class="mx-auto flex max-w-6xl items-center gap-4 py-3
                        lg:py-4">
                <a href="{{ \ArtisanBuild\BuiltForCloud\View\Layout::SCALPELS_URL }}"
                   data-testid="bfc-header-scalpels"
                   class="inline-flex min-h-11 w-24 shrink-0 items-center rounded-xl
                          focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-clay-iron
                          sm:w-32">
                    <img src="{{ $wordmarkUrl }}"
                         alt="Scalpels dashboard"
                         width="480"
                         height="138"
                         class="block h-auto w-full">
                </a>
                <span class="h-7 w-px shrink-0 bg-clay-edge"
                      aria-hidden="true"></span>
                <a href="{{ url('/') }}"
                   data-testid="bfc-header-app"
                   class="inline-flex min-h-11 min-w-0 items-center gap-2.5 rounded-xl text-clay-ink
                          hover:text-clay-brown
                          focus-visible:outline-3 focus-visible:outline-offset-4 focus-visible:outline-clay-iron">
                    <img src="{{ $manifest->imageUrl() }}"
                         alt=""
                         class="size-8 shrink-0 object-contain">
                    <span class="truncate font-display text-lg tracking-tight">
                        {{ $manifest->name }}
                    </span>
                </a>
            </div>
        </header>
    @endif

<main>
    {{ $slot }}
</main>

@stack('scripts')
</body>
</html>
