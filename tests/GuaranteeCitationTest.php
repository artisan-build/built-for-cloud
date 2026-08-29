<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\CitationScan;

/**
 * THE CITATION CONVENTION, checked.
 *
 * This package's security guarantees name the test that pins each of
 * them, because four consecutive review rounds on the Console guard
 * found the same defect: prose claiming more than the code delivered.
 * But a citation is only worth something if it resolves — **a renamed
 * test silently orphans its citation while the document still looks
 * checkable**, which is that same defect one level up.
 *
 * So the citations are parsed and every quoted title has to be a real
 * test. On its first run this found three titles that had gone stale
 * against renames and two abbreviations that were never resolvable,
 * which is the argument for having it.
 */
$citedSurfaces = [
    'src/Console',
    // The enter endpoint's guarantees live on the controller, which is
    // outside src/Console — so it is named explicitly rather than left
    // uncheckable (Console PRD D12/D13, PR4).
    'src/Http/Controllers/ConsoleEnter.php',
    'docs/http-contract.md',
    'release-notes/unified-store-guard.md',
];

it('resolves every test title quoted by a guarantee citation', function () use ($citedSurfaces): void {
    $root = dirname(__DIR__);

    expect(CitationScan::orphansIn($root, $citedSurfaces, $root.'/tests'))->toBe([]);
});

it('is actually reading citations, in every place that carries one', function () use ($citedSurfaces): void {
    // A scanner that matched nothing would report "clean" forever, and
    // the count is per FILE so a citation block deleted wholesale from
    // one document cannot hide behind the others.
    $found = CitationScan::scan(dirname(__DIR__), $citedSurfaces);

    expect(array_keys($found))->toBe([
        'docs/http-contract.md',
        'release-notes/unified-store-guard.md',
        'src/Console/ConsoleEntryState.php',
        'src/Console/ConsoleGuard.php',
        'src/Console/ConsoleSession.php',
        'src/Console/DelegatedActor.php',
        'src/Console/DelegatedActorProvider.php',
        'src/Http/Controllers/ConsoleEnter.php',
    ]);

    expect(array_sum(array_map(count(...), $found)))->toBeGreaterThanOrEqual(35);
});

it('names an orphaned citation when the walk meets one', function (): void {
    // Proven able to fail, on the exact scenario: a claim citing a title
    // that no longer exists because somebody renamed the test.
    $root = sys_get_temp_dir().'/bfc-citation-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);
    mkdir($root.'/tests', 0700, true);

    file_put_contents($root.'/tests/RealTest.php', "<?php\n\nit('a title that really exists', function (): void {});\n");

    file_put_contents($root.'/src/Claim.php', <<<'PHP'
        <?php

        /**
         * Something is guaranteed.
         *   Pinned by `tests/RealTest.php` — "a title that really exists"
         *   and "a title somebody renamed".
         *
         * Prose after the citation, quoting "something that is not a title".
         */
        final class Claim {}
        PHP);

    try {
        // The stale title is NAMED; the live one is not, and the quoted
        // string in the prose AFTER the blank docblock line is outside
        // the citation and is not treated as a title at all.
        expect(CitationScan::orphansIn($root, ['src'], $root.'/tests'))
            ->toBe(['src/Claim.php: "a title somebody renamed"']);

        expect(CitationScan::citedTitlesIn((string) file_get_contents($root.'/src/Claim.php')))
            ->toBe(['a title that really exists', 'a title somebody renamed']);
    } finally {
        array_map(unlink(...), [$root.'/src/Claim.php', $root.'/tests/RealTest.php']);
        rmdir($root.'/src');
        rmdir($root.'/tests');
        rmdir($root);
    }
});

it('reads a title that wraps across lines and docblock markers', function (): void {
    // Every real citation wraps. If normalisation were dropped, the
    // whole suite of citations would go orphaned at once — which would
    // at least be loud — but a partial failure would be worse, so the
    // wrapping is driven directly.
    $docblock = <<<'PHP'
        <?php

        /**
         * A claim.
         *   Pinned by `tests/SomeTest.php` — "a title long enough that it
         *   wraps across a docblock marker and several lines before it
         *   ends".
         */
        PHP;

    expect(CitationScan::citedTitlesIn($docblock))
        ->toBe(['a title long enough that it wraps across a docblock marker and several lines before it ends']);

    $markdown = "Some claim.\n\n*Pinned by* `tests/SomeTest.php` (\"a title that wraps\n  across two markdown lines\").\n\nUnrelated prose quoting \"not a title\".\n";

    expect(CitationScan::citedTitlesIn($markdown))->toBe(['a title that wraps across two markdown lines']);
});

it('refuses an abbreviated citation, because an abbreviation is not checkable', function (): void {
    // The two citations that read "…when the store is still down at save
    // time" were expanded rather than special-cased: a prefix match
    // would have let any abbreviation through, and an abbreviation is
    // exactly what cannot be resolved to a test.
    $root = sys_get_temp_dir().'/bfc-citation-abbrev-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);
    mkdir($root.'/tests', 0700, true);

    file_put_contents($root.'/tests/RealTest.php', "<?php\n\nit('leaves a later request unauthenticated when the store is still down at save time', function (): void {});\n");
    file_put_contents($root.'/src/Claim.php', "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/RealTest.php` — \"…when the store is still down at save time\".\n */\nfinal class Claim {}\n");

    try {
        expect(CitationScan::orphansIn($root, ['src'], $root.'/tests'))
            ->toBe(['src/Claim.php: "…when the store is still down at save time"']);
    } finally {
        array_map(unlink(...), [$root.'/src/Claim.php', $root.'/tests/RealTest.php']);
        rmdir($root.'/src');
        rmdir($root.'/tests');
        rmdir($root);
    }
});
