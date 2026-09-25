<!DOCTYPE html>
<html>
<head><title>custom: {{ $title }}</title>@stack('head')</head>
<body data-testid="custom-layout"><main>{{ $slot }}</main>@stack('scripts')</body>
</html>
