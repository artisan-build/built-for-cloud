<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ReflectionClass;

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
    // Double encoding hides the same origins one layer deeper: each
    // decoded form is checked, so depth buys nothing.
    'double-encoded protocol-relative' => '/%252f%252fevil.example',
    'double-encoded backslash' => '/%255cevil.example',
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

it('refuses an over-length candidate before anything is decoded', function (): void {
    // The length bound is checked on the raw candidate, ahead of every
    // decoding round: a megabyte of base64 never reaches the parser.
    expect(ConsoleReturnTo::relative(str_repeat('a', ConsoleReturnTo::MAX_LENGTH + 1)))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath(str_repeat('a', ConsoleReturnTo::MAX_LENGTH + 1)))->toBeNull()
        // At exactly the bound it is decodable prose again, refused (if
        // at all) by the path rules and not by the size gate.
        ->and(ConsoleReturnTo::relative('/'.str_repeat('a', ConsoleReturnTo::MAX_LENGTH - 1)))->toBe('/'.str_repeat('a', ConsoleReturnTo::MAX_LENGTH - 1));
});

it('refuses a candidate still changing after the decode-round bound instead of guessing what it becomes', function (): void {
    // The NON-SETTLING branch: a candidate percent-encoded deeper than
    // MAX_DECODE_ROUNDS keeps changing on every round the loop runs, so
    // the fixed point is never seen and the honest answer is refusal.
    // Depth is built from the class constant, not hard-coded.
    $maxRounds = (int) (new ReflectionClass(ConsoleReturnTo::class))
        ->getConstant('MAX_DECODE_ROUNDS');

    // One layer: '/%2fevil.example' — decodes to the protocol-relative
    // '//evil.example'. Each further layer wraps the '%' of the layer
    // below ('%2f' -> '%252f' -> '%25252f' -> ...), costing exactly one
    // more round. Every intermediate form stays single-slash-rooted,
    // dot-segment-free printable ASCII, so the rounds pass the safety
    // check and the refusal comes from the bound, not from unsafety.
    $encodedSlashAt = static function (int $depth): string {
        $encoded = '%2f';
        for ($layer = 1; $depth > $layer; $layer++) {
            $encoded = '%25'.substr($encoded, 1);
        }

        return '/'.$encoded.'evil.example';
    };

    // DEEPER than the bound: still changing when the loop ends — refused.
    expect(ConsoleReturnTo::relative($encodedSlashAt($maxRounds + 1)))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath($encodedSlashAt($maxRounds + 1)))->toBeNull();

    // The SAME payload one layer shallower settles inside the bound —
    // and is refused anyway, because what it settles TO is the
    // protocol-relative '//evil.example'. Depth is the only difference
    // between the two candidates, so this test can tell the two refusal
    // branches apart only by which side of the bound the payload sits.
    expect(ConsoleReturnTo::relative($encodedSlashAt($maxRounds)))->toBeNull()
        ->and(ConsoleReturnTo::canonicalPath($encodedSlashAt($maxRounds)))->toBeNull();
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
