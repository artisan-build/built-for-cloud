{{--
    `bfc::layout` — THE ONE PACKAGE LAYOUT (Console PRD D11).

    There is exactly one layout file in this package and there is never a
    second one to choose between. What differs between a local login and
    a delegated console session is what this file renders INSIDE itself,
    driven by the one resolved acting principal (D14) that the
    `bfc::layout` view composer hands in as `$bfcConsoleChrome`. D11 is
    explicit that layout selection is never conditional, and the reason
    is that two layouts drift: the moment "the console layout" exists as
    a separate file, a change to the app's chrome has two places to land
    and one of them gets forgotten.
      Pinned by `tests/ConsoleChromeTest.php` — "renders one and the same
      layout file for a local session and a delegated one".

    A LOCAL SESSION RENDERS ZERO CHROME. Not a collapsed bar, not an
    empty container: the branch below emits nothing at all, and the
    interceptor script is not on the page either, because there is no
    delegated session for it to re-enter.
      Pinned by `tests/ConsoleChromeTest.php` — "renders zero console
      chrome for a local authenticated session".

    HOW AN APP USES IT. Both of Laravel's shapes work and neither is
    required: a Blade page may `@extends('bfc::layout')` and fill
    `@section('content')`, and a component or Livewire page may name this
    view as its layout and arrive as `$slot`. `@push('head')` and
    `@push('scripts')` are the two stacks an app's own assets go in.

--}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('title', config('app.name'))</title>
    @stack('head')
</head>
<body>
@if ($bfcConsoleChrome->delegated)
    @include('bfc::chrome', ['chrome' => $bfcConsoleChrome])
@endif

<main>
    {{ $slot ?? '' }}
    @yield('content')
</main>

@stack('scripts')
</body>
</html>
