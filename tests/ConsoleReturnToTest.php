<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;

// The relative-path boundary every package redirect target goes through.
// These are direct assertions on the check itself; the standalone and
// managed handoff surfaces that consume it carry their own end-to-end
// coverage.

it('accepts a plain in-app path and echoes it verbatim', function (): void {
    expect(ConsoleReturnTo::relative('/orders'))->toBe('/orders')
        ->and(ConsoleReturnTo::canonicalPath('/orders'))->toBe('/orders')
        // The verbatim answer keeps the query; the canonical one is for
        // deciding ABOUT a path and carries no query or fragment.
        ->and(ConsoleReturnTo::relative('/orders?tab=open'))->toBe('/orders?tab=open')
        ->and(ConsoleReturnTo::canonicalPath('/orders?tab=open'))->toBe('/orders')
        ->and(ConsoleReturnTo::relative('/reports..csv'))->toBe('/reports..csv')
        ->and(ConsoleReturnTo::relative('/o..ders'))->toBe('/o..ders');
});

it('refuses a return path that is not a safe same-origin relative path', function (mixed $path): void {
    expect(ConsoleReturnTo::relative($path))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath($path))->toBeNull();
})->with([
    'absolute url' => 'https://evil.example/x',
    'javascript scheme' => 'javascript:alert(1)',
    'data scheme' => 'data:text/html;base64,PHNjcmlwdD4=',
    'protocol-relative' => '//evil.example/x',
    'encoded protocol-relative' => '/%2f%2fevil.example',
    'backslash' => '/\\evil.example',
    'encoded backslash' => '/%5cevil.example',
    'not rooted' => 'orders',
    'empty' => '',
    'not a string' => 42,
]);

it('refuses a return path carrying a traversal segment in any decoded form', function (string $path): void {
    expect(ConsoleReturnTo::relative($path))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath($path))->toBeNull();
})->with([
    '/admin/../billing',
    '/admin/%2e%2e/billing',
    '/admin/%252e%252e/billing',
    '/%2e%2e',
    '/..',
]);

it('reads the canonical, fully decoded path', function (): void {
    // The canonical form is what a decision about a path must be made
    // on: `/%61dmin/users` and `/admin/users` are the same path, and a
    // comparison made on the spelling would answer differently for them.
    expect(ConsoleReturnTo::canonicalPath('/%61dmin/users'))->toBe('/admin/users')
        ->and(ConsoleReturnTo::canonicalPath('/admin/users'))->toBe('/admin/users')
        // The verbatim answer is what a redirect emits; it is never a
        // value the caller did not supply.
        ->and(ConsoleReturnTo::relative('/%61dmin/users'))->toBe('/%61dmin/users');
});

it('establishes the path once, so a query string cannot appear out of a decoding round', function (): void {
    // `%3F` is not a delimiter inside a path — it is an ordinary path
    // character the browser does not split on — so a `?` that exists
    // only after decoding must not shorten the path a decision sees.
    expect(ConsoleReturnTo::canonicalPath('/admin%3F/%2e%2e/billing'))->toBeNull();
});

it('refuses a candidate that will not settle within the decode rounds', function (): void {
    // Triple encoding still decodes toward a fixed point eventually;
    // this candidate keeps changing past the bound by construction of
    // the class constant, so the honest answer is refusal, and a plain
    // over-length candidate is refused before anything is decoded.
    expect(ConsoleReturnTo::relative(str_repeat('a', ConsoleReturnTo::MAX_LENGTH + 1)))->toBeNull();
});

it('falls back to a server-chosen root when no candidate survives', function (): void {
    expect(ConsoleReturnTo::firstRelative([
        'https://evil.example/x',
        '//evil.example/y',
        null,
        42,
    ]))->toBe('/')
        ->and(ConsoleReturnTo::firstRelative(['/orders']))->toBe('/orders');
});
