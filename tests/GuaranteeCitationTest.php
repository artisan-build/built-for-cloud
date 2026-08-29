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
 * The floor is therefore PER FILE. **And the file list is built from
 * what EXISTS, not from what already cites something** — which is the
 * second thing that had to be fixed, because the first attempt at this
 * tripwire was built on `CitationScan::scan()`, and `scan()` omits
 * files with zero citations. A check that can only see files with
 * citations cannot see a file that has none, so the new-file tripwire
 * was claimed and did not exist: the fixture that "proved" it failed
 * only because it had been listed by hand.
 *
 * So every candidate file under the scanned surfaces must be
 * CLASSIFIED — given a citation floor, or listed as exempt with a
 * reason. A new file in `src/Console` reds this suite until somebody
 * says which it is, in the diff. That is deliberate friction and it is
 * the whole property: absence has to be detectable.
 *
 * The candidate walk matches `.md`, `.php` and `.inc`,
 * case-insensitively. An earlier revision matched lower-case `.php`
 * alone, so a `README.md` beside the guard — the likeliest place of all
 * for somebody to write an uncited guarantee, since every document in
 * this package is markdown — existed unclassified while this suite
 * reported clean. That was the same shape a third time: a filter that
 * could not see the thing that was missing.
 *
 * THE RESIDUE, now small and named: a guarantee-bearing file OUTSIDE
 * the scanned surfaces entirely — a new top-level document nobody adds
 * to `$citedSurfaces`. Adding a surface is the human step; everything
 * inside one is mechanical.
 */
$citedSurfaces = [
    'src/Console',
    // The app-action audit stream (Console PRD D17). A whole new
    // directory of guarantee-bearing files, so it is added as a SURFACE
    // rather than file by file: everything under it must be classified
    // from the day it appears, which is the property that failed for the
    // enter endpoint's release note.
    'src/Audit',
    // The enter endpoint's guarantees live on the controller and in its
    // release note, both outside src/Console — so both are named
    // explicitly rather than left uncheckable (Console PRD D12/D13).
    'src/Http/Controllers/ConsoleEnter.php',
    // The console chrome (Console PRD D11/D7). Its guarantees are spread
    // across a value object under src/Console (already a surface), one
    // controller, the two Blade templates and the interceptor script —
    // so the two RESOURCE directories are added as surfaces rather than
    // file by file, for the reason src/Audit was: everything under them
    // must be classified from the day it appears.
    'src/Http/Controllers/ConsoleChromeScript.php',
    'resources/views',
    'resources/js',
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
    'docs/http-contract.md' => 75,
    'src/Audit/AppAction.php' => 5,
    'src/Audit/AppActionActor.php' => 7,
    'src/Audit/AppActionEvent.php' => 14,
    'src/Audit/AppendOnlyBuilder.php' => 2,
    'src/Audit/AppActionOutboxEntry.php' => 9,
    'src/Audit/AppActionRecorder.php' => 7,
    'src/Audit/AppActorType.php' => 1,
    'release-notes/console-enter.md' => 28,
    'release-notes/unified-store-guard.md' => 8,
    'src/Console/AssertionBurn.php' => 6,
    'src/Console/AssertionVerifier.php' => 2,
    'src/Console/ConsoleEntryState.php' => 8,
    'src/Console/ConsoleGuard.php' => 17,
    'src/Console/ConsoleReturnTo.php' => 2,
    'src/Console/ConsoleSession.php' => 2,
    'src/Console/DelegatedActor.php' => 6,
    'src/Console/ConsoleChrome.php' => 6,
    'src/Console/DelegatedActorProvider.php' => 4,
    'src/Console/ServesConsoleChrome.php' => 3,
    'src/Http/Controllers/ConsoleChromeScript.php' => 1,
    'resources/views/chrome.blade.php' => 2,
    'resources/views/layout.blade.php' => 2,
    'resources/js/console-reentry.js' => 8,
    'src/Http/Controllers/ConsoleEnter.php' => 24,
];

/**
 * Candidate files that make no guarantee of their own and therefore
 * cite nothing. Each carries the reason, because an exemption without
 * one is indistinguishable from an oversight — which is what this whole
 * mechanism exists to tell apart.
 *
 * Adding a file to `src/Console` reds the suite until it appears here
 * or in the floor above.
 */
$exemptFromCitation = [
    'src/Audit/AppActionEventBuilder.php' => 'a two-line binding of the shared AppendOnlyBuilder to one model; it adds and overrides nothing, and every claim is on the base',
    'src/Audit/AppActionLedgerBuilder.php' => 'a two-line binding of the shared AppendOnlyBuilder to one model; it adds and overrides nothing, and every claim is on the base',
    'src/Audit/AppActionReason.php' => 'a bounded enum: the closed app-action reason vocabulary, whose doc-to-code check is HttpContractDocTest\'s',
    'src/Audit/ConsoleAction.php' => 'a bounded enum: the package\'s own action vocabulary, whose one case is driven by ConsoleEnterAuditTest',
    'src/Console/ActingPrincipal.php' => 'a readonly value object: the resolved principal, carrying no rule of its own',
    'src/Console/ActingPrincipalResolver.php' => 'D14 precedence, whose guarantees are stated and cited on ConsoleGuard',
    'src/Console/Assertion.php' => 'the verified claim set; every property rule is the verifier\'s and is cited there',
    'src/Console/AssertionRefusalReason.php' => 'a bounded enum of audit reasons',
    'src/Console/ConsoleEntryRefusalReason.php' => 'a bounded enum of audit reasons',
    'src/Console/ConsoleGuardConfiguration.php' => 'guard/provider injection; its rules are driven by ConsoleGuardRegistrationTest and stated in the contract',
    'src/Console/ConsoleKey.php' => 'a keyring row; the custody claim lives on ConsoleKeyring and points elsewhere for its enforcement',
    'src/Console/ConsoleKeyDelivery.php' => 'parses the delivered pair; the authority rules are FileConsoleKey\'s',
    'src/Console/ConsoleKeyFiled.php' => 'a readonly result object',
    'src/Console/ConsoleKeyRefusal.php' => 'a bounded enum of refusal reasons',
    'src/Console/ConsoleKeyring.php' => 'make-before-break rotation; PR2 surface, whose claims are carried in the contract document',
    'src/Console/ConsoleReentryReason.php' => 'a bounded enum the structured 401 carries',
    'src/Console/ConsoleRole.php' => 'the two-value contract vocabulary (D8)',
    'src/Console/ConsoleSessionClock.php' => 'D7\'s cap constant and its fail-closed read; cited from ConsoleGuard, which is where the cap is enforced',
    'src/Console/DelegatedClaims.php' => 'a readonly value object carrying one session\'s claims',
];

/**
 * THE STRICTER FORM, and the files held to it.
 *
 * `orphansIn()` asks only whether a cited title resolves to a test
 * SOMEWHERE, which lets a citation name the wrong file and stay green —
 * and that is how a misattribution survived a hand check on the PR
 * before this one. Two additional rules close it: a citation names
 * exactly ONE test file, and every title it quotes is declared in THAT
 * file.
 *
 * **THE RESIDUE IS THE REASON THIS IS A LIST AND NOT A SURFACE**, and it
 * is named rather than glossed: the documents that landed before this
 * rule existed carry citations that name three test files at once — the
 * contract's session-writer paragraph is one — and rewriting other
 * people's citations is not this change's business. So the rule is
 * enforced where it is enforceable, over the files this release adds,
 * and everything older stays held to the orphan check alone. A file
 * added here is a file that can never drift; a file not here can.
 */
$strictlyCited = [
    'src/Console/ConsoleChrome.php',
    'src/Console/ServesConsoleChrome.php',
    'src/Http/Controllers/ConsoleChromeScript.php',
    'resources/views/layout.blade.php',
    'resources/views/chrome.blade.php',
    'resources/js/console-reentry.js',
    'tests/ConsoleChromeRouteScan.php',
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

it('classifies every candidate file, so a new one that cites nothing cannot hide', function () use ($citedSurfaces, $expectedCitations, $exemptFromCitation): void {
    // THE CHECK THAT DID NOT EXIST. It is built on the files that EXIST
    // under the scanned surfaces, not on the files that already cite
    // something — which is what CitationScan::scan() returns, and why a
    // tripwire built on scan() could never see a document with no
    // citations at all.
    $root = dirname(__DIR__);

    expect(CitationScan::unclassifiedIn($root, $citedSurfaces, $expectedCitations, $exemptFromCitation))
        ->toBe([]);

    // Every exemption carries a reason, because an exemption without
    // one is indistinguishable from an oversight.
    foreach ($exemptFromCitation as $path => $reason) {
        expect($reason)->toBeString()->not->toBe('');
    }

    // The two maps are disjoint: a file is expected to cite, or exempt,
    // never quietly both.
    expect(array_intersect_key($expectedCitations, $exemptFromCitation))->toBe([]);
});

it('names a candidate file that nobody classified', function (): void {
    // Proven able to fail on the exact shape the old tripwire could not
    // see: a NEW file, carrying no citation, that nobody listed. Under
    // the previous mechanism this was invisible — the fixture that
    // stood in for it passed only because it had been added to the
    // expectation by hand.
    $root = sys_get_temp_dir().'/bfc-citation-new-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);

    $cited = "<?php\n\n/**\n * A claim.\n *   Pinned by `tests/T.php` — \"one\".\n */\n";
    $uncited = "<?php\n\n/** Something is guaranteed, and nothing says what pins it. */\n";

    $files = [
        $root.'/src/Listed.php' => $cited,
        $root.'/src/Exempt.php' => $uncited,
        $root.'/src/BrandNew.php' => $uncited,
        // The extensions an earlier revision walked straight past: a
        // markdown README beside the code — the likeliest place of all
        // for an uncited guarantee, since every document in this
        // package is markdown — an `.inc`, and an upper-case `.PHP`.
        $root.'/src/README.md' => "# Something is guaranteed\n\nAnd nothing says what pins it.\n",
        $root.'/src/Legacy.inc' => $uncited,
        $root.'/src/Shouty.PHP' => $uncited,
        // Not a candidate: no extension a guarantee travels in here.
        $root.'/src/notes.txt' => "Something is guaranteed.\n",
    ];

    foreach ($files as $path => $contents) {
        file_put_contents($path, $contents);
    }

    try {
        expect(CitationScan::candidatesIn($root, ['src']))
            ->toBe([
                'src/BrandNew.php',
                'src/Exempt.php',
                'src/Legacy.inc',
                'src/Listed.php',
                'src/README.md',
                'src/Shouty.PHP',
            ])
            ->and(CitationScan::unclassifiedIn(
                $root,
                ['src'],
                ['src/Listed.php' => 1],
                ['src/Exempt.php' => 'a value object'],
            ))->toBe(['src/BrandNew.php', 'src/Legacy.inc', 'src/README.md', 'src/Shouty.PHP']);
    } finally {
        array_map(unlink(...), array_keys($files));
        rmdir($root.'/src');
        rmdir($root);
    }
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

it('holds the console chrome to one test file per citation, and to the file it names', function () use ($strictlyCited): void {
    $root = dirname(__DIR__);

    expect(CitationScan::multiFileCitationsIn($root, $strictlyCited))->toBe([])
        ->and(CitationScan::misattributedIn($root, $strictlyCited, $root.'/tests'))->toBe([]);

    // NOT VACUOUS: every file on the strict list actually carries
    // citations. A path typo would otherwise read as compliance.
    foreach ($strictlyCited as $path) {
        expect(CitationScan::countCitationsIn((string) file_get_contents($root.'/'.$path)))
            ->toBeGreaterThan(0, $path.' is on the strict list but cites nothing.');
    }
});

it('names a citation that points at the wrong test file, and one that points at several', function (): void {
    // Proven able to fail, on both shapes. The first is the one an
    // orphan check cannot see: the title is real, the file is wrong, and
    // a reader following the citation lands somewhere that does not
    // contain it.
    $root = sys_get_temp_dir().'/bfc-citation-strict-'.bin2hex(random_bytes(6));

    mkdir($root.'/src', 0700, true);
    mkdir($root.'/tests', 0700, true);

    file_put_contents($root.'/tests/RightTest.php', "<?php\n\nit('a title that lives here', function (): void {});\n");
    file_put_contents($root.'/tests/WrongTest.php', "<?php\n\nit('a title that lives somewhere else', function (): void {});\n");

    file_put_contents($root.'/src/Misattributed.php', <<<'PHP'
        <?php

        /**
         * A claim.
         *   Pinned by `tests/RightTest.php` — "a title that lives here"
         *   and "a title that lives somewhere else".
         */
        PHP);

    file_put_contents($root.'/src/MultiFile.php', <<<'PHP'
        <?php

        /**
         * A claim.
         *   Pinned by `tests/RightTest.php` ("a title that lives here")
         *   and `tests/WrongTest.php` ("a title that lives somewhere
         *   else").
         */
        PHP);

    $paths = ['src/Misattributed.php', 'src/MultiFile.php'];

    try {
        expect(CitationScan::misattributedIn($root, $paths, $root.'/tests'))
            ->toBe(['src/Misattributed.php: "a title that lives somewhere else" is cited to tests/RightTest.php but declared in tests/WrongTest.php'])
            ->and(CitationScan::multiFileCitationsIn($root, $paths))
            ->toBe(['src/MultiFile.php: names 2 files']);
    } finally {
        array_map(unlink(...), [
            $root.'/src/Misattributed.php',
            $root.'/src/MultiFile.php',
            $root.'/tests/RightTest.php',
            $root.'/tests/WrongTest.php',
        ]);
        rmdir($root.'/src');
        rmdir($root.'/tests');
        rmdir($root);
    }
});
