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
 *
 * **AND THEN IT MISSED THE FIRST PR WRITTEN AFTER IT SHIPPED.** The
 * enter endpoint's release note was not a scanned surface at all, and
 * its contract section made a page of guarantees while citing nothing —
 * and the suite stayed green, because an orphan check can only check
 * citations that already exist, and the aggregate floor it leaned on was
 * satisfied by older files' counts. A convention that cannot notice a
 * new document making uncited claims is not enforcing anything about new
 * work, which is the only work that needs enforcing.
 *
 * The floor is therefore PER FILE. Every surface expected to carry
 * guarantees is named with the number of citations it must carry, so a
 * document that drops its citations reds, and a new guarantee-bearing
 * file that cites nothing reds the moment it is added to the list.
 *
 * THE RESIDUE, named because an enumeration always has one: a brand-new
 * guarantee-bearing file that nobody adds to `$citedSurfaces` is
 * invisible here. Adding it is the human step; everything after that is
 * mechanical. This is a tripwire against the ordinary omission, not a
 * proof about every file that could exist.
 */
$citedSurfaces = [
    'src/Console',
    // The enter endpoint's guarantees live on the controller and in its
    // release note, both outside src/Console — so both are named
    // explicitly rather than left uncheckable (Console PRD D12/D13).
    'src/Http/Controllers/ConsoleEnter.php',
    'docs/http-contract.md',
    'release-notes/console-enter.md',
    'release-notes/unified-store-guard.md',
];

/**
 * The per-file floor: how many cited titles each guarantee-bearing
 * surface must carry. A MINIMUM, not an exact count — adding a citation
 * is always welcome — so what this catches is a file that loses them,
 * and a file that is expected to have them and has none at all.
 */
$expectedCitations = [
    'docs/http-contract.md' => 40,
    'release-notes/console-enter.md' => 18,
    'release-notes/unified-store-guard.md' => 8,
    'src/Console/AssertionBurn.php' => 6,
    'src/Console/AssertionVerifier.php' => 2,
    'src/Console/ConsoleEntryState.php' => 8,
    'src/Console/ConsoleGuard.php' => 17,
    'src/Console/ConsoleReturnTo.php' => 2,
    'src/Console/ConsoleSession.php' => 2,
    'src/Console/DelegatedActor.php' => 6,
    'src/Console/DelegatedActorProvider.php' => 4,
    'src/Http/Controllers/ConsoleEnter.php' => 16,
];

it('resolves every test title quoted by a guarantee citation', function () use ($citedSurfaces): void {
    $root = dirname(__DIR__);

    expect(CitationScan::orphansIn($root, $citedSurfaces, $root.'/tests'))->toBe([]);
});

it('holds every guarantee-bearing surface to its own citation floor', function () use ($citedSurfaces, $expectedCitations): void {
    // The two halves fail differently, and the second is the one the
    // aggregate floor could not express: a file that is supposed to
    // carry guarantees and cites NOTHING has no citation to orphan and
    // contributes nothing to a total, so only a per-file expectation
    // sees it.
    $root = dirname(__DIR__);

    expect(CitationScan::shortfallsIn($root, $citedSurfaces, $expectedCitations))->toBe([])
        ->and(CitationScan::unexpectedIn($root, $citedSurfaces, $expectedCitations))->toBe([]);
});

it('names a file that cites less than it is expected to, and one nobody expected at all', function (): void {
    // Proven able to fail, on both scenarios that matter: a document
    // that dropped its citations, and a NEW guarantee-bearing file that
    // was never added to the expectation.
    $root = sys_get_temp_dir().'/bfc-citation-floor-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);

    file_put_contents($root.'/src/Kept.php', "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/T.php` — \"one\" and \"two\".\n */\n");
    file_put_contents($root.'/src/Thinned.php', "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/T.php` — \"one\".\n */\n");
    file_put_contents($root.'/src/Unlisted.php', "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/T.php` — \"one\".\n */\n");
    // Expected to carry citations and carries none — the shape the
    // release note had, and the reason this test exists.
    file_put_contents($root.'/src/Silent.php', "<?php\n\n/** Something is simply asserted, with nothing behind it. */\n");

    $expected = ['src/Kept.php' => 2, 'src/Thinned.php' => 2, 'src/Silent.php' => 1];

    try {
        expect(CitationScan::shortfallsIn($root, ['src'], $expected))->toBe([
            'src/Silent.php: expected 1, found 0',
            'src/Thinned.php: expected 2, found 1',
        ]);

        expect(CitationScan::unexpectedIn($root, ['src'], $expected))->toBe(['src/Unlisted.php']);
    } finally {
        array_map(unlink(...), [$root.'/src/Kept.php', $root.'/src/Thinned.php', $root.'/src/Unlisted.php', $root.'/src/Silent.php']);
        rmdir($root.'/src');
        rmdir($root);
    }
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

it('resolves a PHPUnit-style case the way Pest prints it', function (): void {
    // Some facts can only be driven PHPUnit-style — a config key
    // consumed at provider boot has to be in place before the
    // application exists — and until this release a citation could not
    // name one, which pushed those guarantees towards citing nothing.
    $root = sys_get_temp_dir().'/bfc-citation-phpunit-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);
    mkdir($root.'/tests', 0700, true);

    file_put_contents(
        $root.'/tests/SurfaceTest.php',
        "<?php\n\nfinal class SurfaceTest\n{\n    public function test_the_door_is_mounted_by_default(): void {}\n}\n",
    );
    file_put_contents(
        $root.'/src/Claim.php',
        "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/SurfaceTest.php` — \"the door is mounted by default\"\n *   and \"the_door_is_mounted_by_default\".\n */\n",
    );

    try {
        // The humanised form resolves; the raw method name does not,
        // because that is not what a reader sees in the output.
        expect(CitationScan::orphansIn($root, ['src'], $root.'/tests'))
            ->toBe(['src/Claim.php: "the_door_is_mounted_by_default"']);
    } finally {
        array_map(unlink(...), [$root.'/src/Claim.php', $root.'/tests/SurfaceTest.php']);
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
