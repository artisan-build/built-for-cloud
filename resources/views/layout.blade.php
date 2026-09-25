{{--
    The default Built for Cloud shell, rendered by
    ArtisanBuild\BuiltForCloud\View\Layout for `<x-bfc-layout>` and for every
    full-page Livewire component.

    There is one layout and it is chosen by configuration, never by editing
    this file: an app that wants a different shell names its own Component
    class in BUILT_FOR_CLOUD_LAYOUT. Pages add their own assets to the
    `head` and `scripts` stacks.
--}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title }}</title>
    @stack('head')
</head>
<body data-testid="bfc-layout">
<main>
    {{ $slot }}
</main>

@stack('scripts')
</body>
</html>
