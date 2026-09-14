<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $manifest->name }}</title>
</head>
<body>
<main data-testid="landing" data-app-slug="{{ $manifest->slug }}">
    <img data-testid="landing-manifest-icon" src="{{ $manifest->icon }}" alt="{{ $manifest->name }}">
    <h1 data-testid="landing-manifest-name">{{ $manifest->name }}</h1>
    <p data-testid="landing-manifest-description">{{ $manifest->description }}</p>
    <a data-testid="landing-manifest-product-link" href="{{ $manifest->productUrl }}">{{ $manifest->productUrl }}</a>
    <a data-testid="landing-ui-entry" href="{{ url('/bfc/ui') }}">Open application</a>
</main>
</body>
</html>
