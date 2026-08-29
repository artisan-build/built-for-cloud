{{--
    THE DELEGATED CHROME (Console PRD D4 / D11) — included from
    `bfc::layout` and from nowhere else, and only on the delegated
    branch.

    EVERY DISPLAY VALUE HERE IS A BLADE `{{ }}` ECHO, in an element body
    or inside a double-quoted attribute, and never in a script, a style,
    an unquoted attribute or a URL position. That is what makes a
    hostile display claim inert: `{{ }}` escapes with `ENT_QUOTES`, so
    `<img src=x onerror=alert(1)>` renders as text and a quote cannot
    break out of the `title` attribute it lands in. The values arrive
    already bounded by `ConsoleChrome`, which refuses an over-long,
    control-bearing or invalid-UTF-8 claim rather than trimming it —
    bounding and escaping are two different jobs and this file does the
    second.
      Pinned by `tests/ConsoleChromeTest.php` — "renders a hostile
      display name, agency and issuer inert".

    THE ROLE IS AN ENUM, so `data-bfc-console-role` carries a value from
    a two-case vocabulary (D8) and can never carry issuer text.

    THE SCRIPT TAG IS OMITTED ENTIRELY when the interceptor route is not
    mounted, rather than pointing at a URL nobody serves.
      Pinned by `tests/ConsoleChromeUnmountedTest.php` — "renders no
      reentry script when the interceptor route is not mounted".

--}}
<div id="{{ \ArtisanBuild\BuiltForCloud\Console\ConsoleChrome::ELEMENT_ID }}"
     role="status"
     data-bfc-console-chrome="1"
     data-bfc-console-role="{{ $chrome->role?->value }}">
    <span data-bfc-console-operator title="{{ $chrome->operatorLabel() }}">{{ $chrome->operatorLabel() }}</span>
    @if ($chrome->agency !== null)
        <span data-bfc-console-agency title="{{ $chrome->agency }}">({{ $chrome->agency }})</span>
    @endif
    @if ($chrome->issuer !== null)
        <span data-bfc-console-issuer title="{{ $chrome->issuer }}">via {{ $chrome->issuer }}</span>
    @endif
    <span data-bfc-console-role-label>{{ $chrome->role?->value }}</span>
</div>
@if ($chrome->scriptUrl !== null)
    <script src="{{ $chrome->scriptUrl }}" defer></script>
@endif
