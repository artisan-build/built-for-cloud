{{--
    `bfc::layout` — THE ONE PACKAGE LAYOUT.

    There is exactly one layout file in this package and there is never a
    second one to choose between, because two layouts drift: the moment a
    variant exists as a separate file, a change to the app's chrome has
    two places to land and one of them gets forgotten.

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
<main>
    {{ $slot ?? '' }}
    @yield('content')
</main>

@stack('scripts')
</body>
</html>
